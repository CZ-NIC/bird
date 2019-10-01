/*
 *	BIRD Library -- Formatted Output
 *
 *	(c) 1991, 1992 Lars Wirzenius & Linus Torvalds
 *
 *	Hacked up for BIRD by Martin Mares <mj@ucw.cz>
 *	Buffer size limitation implemented by Martin Mares.
 */

#include "nest/bird.h"
#include "string.h"

#include <errno.h>

#include "nest/iface.h"

/* we use this so that we can do without the ctype library */
#define is_digit(c)	((c) >= '0' && (c) <= '9')

static int skip_atoi(const char **s)
{
	int i=0;

	while (is_digit(**s))
		i = i*10 + *((*s)++) - '0';
	return i;
}

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SPECIAL	32		/* 0x */
#define LARGE	64		/* use 'ABCDEF' instead of 'abcdef' */

static char * number(char * str, u64 num, uint base, int size, int precision,
	int type, int remains)
{
	char c,sign,tmp[66];
	const char *digits="0123456789abcdefghijklmnopqrstuvwxyz";
	int i;

	if (size >= 0 && (remains -= size) < 0)
		return NULL;
	if (type & LARGE)
		digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	if (type & LEFT)
		type &= ~ZEROPAD;
	if (base < 2 || base > 36)
		return 0;
	c = (type & ZEROPAD) ? '0' : ' ';
	sign = 0;
	if (type & SIGN) {
		if (num > (u64) INT64_MAX) {
			sign = '-';
			num = -num;
			size--;
		} else if (type & PLUS) {
			sign = '+';
			size--;
		} else if (type & SPACE) {
			sign = ' ';
			size--;
		}
	}
	if (type & SPECIAL) {
		if (base == 16)
			size -= 2;
		else if (base == 8)
			size--;
	}
	i = 0;
	if (num == 0)
		tmp[i++]='0';
	else while (num != 0) {
		uint res = num % base;
		num = num / base;
		tmp[i++] = digits[res];
	}
	if (i > precision)
		precision = i;
	size -= precision;
	if (size < 0 && -size > remains)
		return NULL;
	if (!(type&(ZEROPAD+LEFT)))
		while(size-->0)
			*str++ = ' ';
	if (sign)
		*str++ = sign;
	if (type & SPECIAL) {
		if (base==8)
			*str++ = '0';
		else if (base==16) {
			*str++ = '0';
			*str++ = digits[33];
		}
	}
	if (!(type & LEFT))
		while (size-- > 0)
			*str++ = c;
	while (i < precision--)
		*str++ = '0';
	while (i-- > 0)
		*str++ = tmp[i];
	while (size-- > 0)
		*str++ = ' ';
	return str;
}

/**
 * bvsnprintf - BIRD's vsnprintf()
 * @buf: destination buffer
 * @size: size of the buffer
 * @fmt: format string
 * @args: a list of arguments to be formatted
 *
 * This functions acts like ordinary sprintf() except that it checks available
 * space to avoid buffer overflows and it allows some more format specifiers:
 * |%I| for formatting of IP addresses (width of 1 is automatically replaced by
 * standard IP address width which depends on whether we use IPv4 or IPv6; |%I4|
 * or |%I6| can be used for explicit ip4_addr / ip6_addr arguments, |%N| for
 * generic network addresses (net_addr *), |%R| for Router / Network ID (u32
 * value printed as IPv4 address), |%lR| for 64bit Router / Network ID (u64
 * value printed as eight :-separated octets), |%t| for time values (btime) with
 * specified subsecond precision, and |%m| resp. |%M| for error messages (uses
 * strerror() to translate @errno code to message text). On the other hand, it
 * doesn't support floating point numbers. The bvsnprintf() supports |%h| and
 * |%l| qualifiers, but |%l| is used for s64/u64 instead of long/ulong.
 *
 * Result: number of characters of the output string or -1 if
 * the buffer space was insufficient.
 */
int bvsnprintf(char *buf, int size, const char *fmt, va_list args)
{
	int len, i;
	u64 num;
	uint base;
	u32 x;
	u64 X;
	btime t;
	s64 t1, t2;
	char *str, *start;
	const char *s;
	char ipbuf[NET_MAX_TEXT_LENGTH+1];
	struct iface *iface;

	int flags;		/* flags to number() */

	int field_width;	/* width of output field */
	int precision;		/* min. # of digits for integers; max
				   number of chars for from string */
	int qualifier;		/* 'h' or 'l' for integer fields */

	for (start=str=buf ; *fmt ; ++fmt, size-=(str-start), start=str) {
		if (*fmt != '%') {
			if (!size)
				return -1;
			*str++ = *fmt;
			continue;
		}

		/* process flags */
		flags = 0;
		repeat:
			++fmt;		/* this also skips first '%' */
			switch (*fmt) {
				case '-': flags |= LEFT; goto repeat;
				case '+': flags |= PLUS; goto repeat;
				case ' ': flags |= SPACE; goto repeat;
				case '#': flags |= SPECIAL; goto repeat;
				case '0': flags |= ZEROPAD; goto repeat;
			}

		/* get field width */
		field_width = -1;
		if (is_digit(*fmt))
			field_width = skip_atoi(&fmt);
		else if (*fmt == '*') {
			++fmt;
			/* it's the next argument */
			field_width = va_arg(args, int);
			if (field_width < 0) {
				field_width = -field_width;
				flags |= LEFT;
			}
		}

		/* get the precision */
		precision = -1;
		if (*fmt == '.') {
			++fmt;
			if (is_digit(*fmt))
				precision = skip_atoi(&fmt);
			else if (*fmt == '*') {
				++fmt;
				/* it's the next argument */
				precision = va_arg(args, int);
			}
			if (precision < 0)
				precision = 0;
		}

		/* get the conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
			qualifier = *fmt;
			++fmt;
		}

		/* default base */
		base = 10;

		if (field_width > size)
			return -1;
		switch (*fmt) {
		case 'c':
			if (!(flags & LEFT))
				while (--field_width > 0)
					*str++ = ' ';
			*str++ = (byte) va_arg(args, int);
			while (--field_width > 0)
				*str++ = ' ';
			continue;

		case 'm':
			if (flags & SPECIAL) {
				if (!errno)
					continue;
				if (size < 2)
					return -1;
				*str++ = ':';
				*str++ = ' ';
				start += 2;
				size -= 2;
			}
			s = strerror(errno);
			goto str;
		case 'M':
			s = strerror(va_arg(args, int));
			goto str;
		case 'N': {
			net_addr *n = va_arg(args, net_addr *);
			if (field_width == 1)
				field_width = net_max_text_length[n->type];
			net_format(n, ipbuf, sizeof(ipbuf));
			s = ipbuf;
			goto str;
			}
		case 's':
			s = va_arg(args, char *);
			if (!s)
				s = "<NULL>";

		str:
			len = strlen(s);
			if (precision >= 0 && len > precision)
				len = precision;
			if (len > size)
				return -1;

			if (!(flags & LEFT))
				while (len < field_width--)
					*str++ = ' ';
			for (i = 0; i < len; ++i)
				*str++ = *s++;
			while (len < field_width--)
				*str++ = ' ';
			continue;

		case 'V': {
			const char *vfmt = va_arg(args, const char *);
			va_list *vargs = va_arg(args, va_list *);
			int res = bvsnprintf(str, size, vfmt, *vargs);
			if (res < 0)
				return -1;
			str += res;
			size -= res;
			continue;
			}

		case 'p':
			if (field_width == -1) {
				field_width = 2*sizeof(void *);
				flags |= ZEROPAD;
			}
			str = number(str, (uintptr_t) va_arg(args, void *), 16,
				     field_width, precision, flags, size);
			if (!str)
				return -1;
			continue;

		case 'n':
			if (qualifier == 'l') {
				s64 * ip = va_arg(args, s64 *);
				*ip = (str - buf);
			} else {
				int * ip = va_arg(args, int *);
				*ip = (str - buf);
			}
			continue;

		/* IP address */
		case 'I':
			if (fmt[1] == '4') {
				/* Explicit IPv4 address */
				ip4_addr a = va_arg(args, ip4_addr);
				ip4_ntop(a, ipbuf);
				i = IP4_MAX_TEXT_LENGTH;
				fmt++;
			} else if (fmt[1] == '6') {
				/* Explicit IPv6 address */
				ip6_addr a = va_arg(args, ip6_addr);
				ip6_ntop(a, ipbuf);
				i = IP6_MAX_TEXT_LENGTH;
				fmt++;
			} else {
				/* Just IP address */
				ip_addr a = va_arg(args, ip_addr);

				if (ipa_is_ip4(a)) {
					ip4_ntop(ipa_to_ip4(a), ipbuf);
					i = IP4_MAX_TEXT_LENGTH;
				} else {
					ip6_ntop(ipa_to_ip6(a), ipbuf);
					i = IP6_MAX_TEXT_LENGTH;
				}
			}

			s = ipbuf;
			if (field_width == 1)
				field_width = i;

			goto str;

		/* Interface scope after link-local IP address */
		case 'J':
			iface = va_arg(args, struct iface *);
			if (!iface)
				continue;
			if (!size)
				return -1;

			*str++ = '%';
			start++;
			size--;

			s = iface->name;
			goto str;

		/* Router/Network ID - essentially IPv4 address in u32 value */
		case 'R':
			if (qualifier == 'l') {
				X = va_arg(args, u64);
				bsprintf(ipbuf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
					 (uint) ((X >> 56) & 0xff),
					 (uint) ((X >> 48) & 0xff),
					 (uint) ((X >> 40) & 0xff),
					 (uint) ((X >> 32) & 0xff),
					 (uint) ((X >> 24) & 0xff),
					 (uint) ((X >> 16) & 0xff),
					 (uint) ((X >> 8) & 0xff),
					 (uint) (X & 0xff));
			}
			else
			{
				x = va_arg(args, u32);
				ip4_ntop(ip4_from_u32(x), ipbuf);
			}
			s = ipbuf;
			goto str;

		case 't':
			t = va_arg(args, btime);
			t1 = t TO_S;
			t2 = t - t1 S;

			if (precision < 0)
			  precision = 3;

			if (precision > 6)
			  precision = 6;

			/* Compute field_width for second part */
			if ((precision > 0) && (field_width > 0))
			  field_width -= (1 + precision);

			if (field_width < 0)
			  field_width = 0;

			/* Print seconds */
			flags |= SIGN;
			str = number(str, (u64) t1, 10, field_width, 0, flags, size);
			if (!str)
			  return -1;

			if (precision > 0)
			{
			  size -= (str-start);
			  start = str;

			  if ((1 + precision) > size)
			    return -1;

			  /* Convert microseconds to requested precision */
			  for (i = precision; i < 6; i++)
			    t2 /= 10;

			  /* Print sub-seconds */
			  *str++ = '.';
			  str = number(str, (u64) t2, 10, precision, 0, ZEROPAD, size - 1);
			  if (!str)
			    return -1;
			}
			goto done;

		/* integer number formats - set up the flags and "break" */
		case 'o':
			base = 8;
			break;

		case 'X':
			flags |= LARGE;
			/* fallthrough */
		case 'x':
			base = 16;
			break;

		case 'd':
		case 'i':
			flags |= SIGN;
		case 'u':
			break;

		default:
			if (size < 2)
				return -1;
			if (*fmt != '%')
				*str++ = '%';
			if (*fmt)
				*str++ = *fmt;
			else
				--fmt;
			continue;
		}
		if (flags & SIGN) {
			/* Conversions valid per ISO C99 6.3.1.3 (2) */
			if (qualifier == 'l')
				num = (u64) va_arg(args, s64);
			else if (qualifier == 'h')
				num = (u64) (short) va_arg(args, int);
			else
				num = (u64) va_arg(args, int);
		} else {
			if (qualifier == 'l')
				num = va_arg(args, u64);
			else if (qualifier == 'h')
				num = (unsigned short) va_arg(args, int);
			else
				num = va_arg(args, uint);
		}
		str = number(str, num, base, field_width, precision, flags, size);
		if (!str)
			return -1;
	done:	;
	}
	if (!size)
		return -1;
	*str = '\0';
	return str-buf;
}

/**
 * bvsprintf - BIRD's vsprintf()
 * @buf: buffer
 * @fmt: format string
 * @args: a list of arguments to be formatted
 *
 * This function is equivalent to bvsnprintf() with an infinite
 * buffer size. Please use carefully only when you are absolutely
 * sure the buffer won't overflow.
 */
int bvsprintf(char *buf, const char *fmt, va_list args)
{
  return bvsnprintf(buf, 1000000000, fmt, args);
}

/**
 * bsprintf - BIRD's sprintf()
 * @buf: buffer
 * @fmt: format string
 *
 * This function is equivalent to bvsnprintf() with an infinite
 * buffer size and variable arguments instead of a &va_list.
 * Please use carefully only when you are absolutely
 * sure the buffer won't overflow.
 */
int bsprintf(char * buf, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i=bvsnprintf(buf, 1000000000, fmt, args);
  va_end(args);
  return i;
}

/**
 * bsnprintf - BIRD's snprintf()
 * @buf: buffer
 * @size: buffer size
 * @fmt: format string
 *
 * This function is equivalent to bsnprintf() with variable arguments instead of a &va_list.
 */
int bsnprintf(char * buf, int size, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i=bvsnprintf(buf, size, fmt, args);
  va_end(args);
  return i;
}

int
buffer_vprint(buffer *buf, const char *fmt, va_list args)
{
  int i = bvsnprintf((char *) buf->pos, buf->end - buf->pos, fmt, args);

  if ((i < 0) && (buf->pos < buf->end))
    *buf->pos = 0;

  buf->pos = (i >= 0) ? (buf->pos + i) : buf->end;
  return i;
}

int
buffer_print(buffer *buf, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i = bvsnprintf((char *) buf->pos, buf->end - buf->pos, fmt, args);
  va_end(args);

  if ((i < 0) && (buf->pos < buf->end))
    *buf->pos = 0;

  buf->pos = (i >= 0) ? (buf->pos + i) : buf->end;
  return i;
}

void
buffer_puts(buffer *buf, const char *str)
{
  byte *bp = buf->pos;
  byte *be = buf->end - 1;

  while (bp < be && *str)
    *bp++ = *str++;

  if (bp <= be)
    *bp = 0;

  buf->pos = (bp < be) ? bp : buf->end;
}
