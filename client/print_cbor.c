#include <time.h>
#include <stdio.h>
//#include "nest/cbor_parse_tools.h" TODO remove me
#include "nest/cbor_parse.h"
#include "nest/cbor_shortcuts.h"

void print_with_size(byte *string, int len)
{
  for (int i = 0; i < len; i++)
  {
    if (string[i] != '_')
      putc(string[i], stdout);
    else
      putc(' ', stdout);
  }
}

void print_as_time(long int t)
{
  int t1 = t TO_S;
  int t2 = t - t1 S;
  while (t2 > 999)
    t2 = t2/10;
  printf("%i.%i", t1, t2);
}

void print_with_size_(byte *string, int len)
{
  for (int i = 0; i < len; i++)
  {
    putc(string[i], stdout);
  }
}

void print_with_size_add_space(byte *string, int len, int desired_len)
{
  for (int i = 0; i < len; i++)
  {
    putc(string[i], stdout);
  }
  for (int i = 0; i < desired_len - len; i++)
  {
    putc(' ', stdout);
  }
}

void print_ip_addr(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); // tag
  char buff[NET_MAX_TEXT_LENGTH+1];
  int tag = val.val;
  val = get_value(buf_read); // bytestring
  if (tag == 52)
  {
    for (int i = 0; i < val.val-1; i++)
    {
      printf("%i.", buf_read->buff[buf_read->pt + i]);
    }
    printf("%i", buf_read->buff[buf_read->pt + val.val-1]);
  }
  else
  {
    ip6_addr a;// = (ip6_addr*) &buf_read->buff[buf_read->pt];
    for (int i = 0; i < 4; i++)
    {
      a.addr[i] = 0;
      for (int j = 0; j < 4; j++)
      {
        a.addr[i] = a.addr[i] << 8;
        a.addr[i] += buf_read->buff[buf_read->pt + 4 * i + j];
      }
    }
    ip6_ntop(a, buff);
    printf("%s", buff);
  }
  buf_read->pt+=val.val;
}

void print_ip_prefix(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); // tag
  val = get_value(buf_read); // block
  val = get_value(buf_read);
  long prefix = val.val;
  val = get_value(buf_read); // bytestring
  for (int i = 0; i < val.val-1; i++)
  {
    printf("%i.", buf_read->buff[buf_read->pt + i]);
  }
  printf("%i/%li", buf_read->buff[buf_read->pt + val.val], prefix);
  buf_read->pt+=val.val;
}

void print_distance(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(compare_buff_str(buf_read, val.val, "distance"));
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  if (val.major == UINT)
  {
    printf("\t\tdistance %li\n", val.val);
    return;
  }
  else if (val.major == TEXT)
  {
    printf("\t\tdistance ");
    print_with_size_(&buf_read->buff[buf_read->pt], val.val);
    buf_read->pt+=val.val;
    printf("\n");
    return;
  }
  bug("print distance on incorrect type %i\n", val.major);
}

void discard_key(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  if(!(val.major == TEXT))
  {
    bug("key is not text but %i", val.major);
  }
  buf_read->pt+=val.val;
}

void print_time(int64_t time)
{
  struct tm tm = *localtime(&time);
  printf("%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

}

void print_string_string(struct buff_reader *buf_read, char *str)
{
  discard_key(buf_read);
  printf("%s", str);
  struct value val = get_value(buf_read);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt += val.val;
}

void print_lsa_router(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  discard_key(buf_read);
  printf("\trouter ");
  print_ip_addr(buf_read);
  printf("\n");
  print_distance(buf_read);
  discard_key(buf_read);  // vlink
  val = get_value(buf_read);
  ASSERT(val.major == ARRAY);
  val = get_value(buf_read);
  while (!val_is_break(val))
  {
    discard_key(buf_read);
    printf("\t\tvlink ");
    print_ip_addr(buf_read);
    discard_key(buf_read);
    val = get_value(buf_read);
    printf(" metric %li\n", val.val);
    val = get_value(buf_read);
  }

  discard_key(buf_read);  // router metric
  val = get_value(buf_read);
  ASSERT(val.major == ARRAY);
  val = get_value(buf_read);
  while (!val_is_break(val))
  {
    discard_key(buf_read);
    printf("\t\trouter ");
    print_ip_addr(buf_read);
    val = get_value(buf_read);
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    printf(" metric %li\n", val.val);
    val = get_value(buf_read);
  }

  discard_key(buf_read);  // network
  val = get_value(buf_read);
  ASSERT(val.major == ARRAY);
  val = get_value(buf_read);
  while (!val_is_break(val))
  {
    ASSERT(val.major == BLOCK);
    int block_len = val.val;
    discard_key(buf_read); // dummy id
    val = get_value(buf_read); //id num
    discard_key(buf_read); // network
    int bracket = !(block_len == 4 && buf_read->buff[buf_read->pt + 8] == 'l');
    printf("\t\tnetwork ");
    if (bracket)
      printf("[");
    print_ip_addr(buf_read);
    val = get_value(buf_read);
    if (compare_buff_str(buf_read, val.val, "nif"))
    {
      printf("-");
      buf_read->pt+=val.val;
      val = get_value(buf_read);
      printf("%li", val.val);
    }
    else if (compare_buff_str(buf_read, val.val, "len"))
    {
      printf("/");
      buf_read->pt+=val.val;
      val = get_value(buf_read);
      printf("%li", val.val);
    }
    if (bracket)
      printf("]");
    discard_key(buf_read);
    val = get_value(buf_read);
    printf(" metric %li\n", val.val);
    val = get_value(buf_read);
  }
  val = get_value(buf_read);
  if (!val_is_break(val))
  {
    val = get_value(buf_read); // open list
    while (!val_is_break(val))
    {
      buf_read->pt+=val.val; // stubnet
      val = get_value(buf_read); // open block
      discard_key(buf_read); // stubnet
      printf("\t\tstubnet ");
      val = get_value(buf_read);
      print_ip_addr(buf_read);
      discard_key(buf_read); // len
      val = get_value(buf_read);
      printf("/%li", val.val);
      discard_key(buf_read); // metric
      val = get_value(buf_read);
      printf(" metric %li\n", val.val);
    }
    val = get_value(buf_read);
  }
}


void print_lsa_network(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  if (compare_buff_str(buf_read, val.val, "ospf2"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == BLOCK);
    discard_key(buf_read); // network
    printf("\tnetwork ");
    print_ip_addr(buf_read);
    printf("/");
    discard_key(buf_read); // optx
    val = get_value(buf_read);
    printf("%li\n", val.val);

    discard_key(buf_read); // dr
    printf("\t\tdr ");
    print_ip_addr(buf_read);
    printf("\n");
  }
  else if (compare_buff_str(buf_read, val.val, "ospf"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == BLOCK);
    discard_key(buf_read); // network
    printf("\tnetwork ");
    print_ip_addr(buf_read);
    discard_key(buf_read); // lsa id
    val = get_value(buf_read);
    printf("-%li\n", val.val);
  }
  print_distance(buf_read);
  discard_key(buf_read); // routers
  val = get_value(buf_read);
  ASSERT(val.major == ARRAY);
  val = get_value(buf_read);
  while (!val_is_break(val))
  {
    discard_key(buf_read);
    printf("\t\trouter ");
    print_ip_addr(buf_read);
    printf("\n");
    val = get_value(buf_read);
  }
}


void print_lsa_sum_net(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  discard_key(buf_read);
  printf("\t\txnetwork ");
  print_ip_prefix(buf_read);
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("metric %li\n", val.val);
}


void print_lsa_sum_rt(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  discard_key(buf_read);
  printf("\t\txrouter ");
  print_ip_addr(buf_read);
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("metric %li\n", val.val);
}


void print_lsa_external(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  int via = 0;
  if (compare_buff_str(buf_read, val.val, "via"))
  {
    buf_read->pt+=val.val;
    via = buf_read->pt;
    val = get_value(buf_read); // tag
    val = get_value(buf_read); // bytestring
    buf_read->pt+=val.val;
    val = get_value(buf_read);
  }
  long tag = -1;
  if (compare_buff_str(buf_read, val.val, "tag"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    tag = val.val;
    val = get_value(buf_read);
  }
  discard_key(buf_read); // lsa type
  printf("\t\t");
  val = get_value(buf_read);
  print_with_size_(&buf_read->buff[buf_read->pt], val.val);
  printf(" ");
  discard_key(buf_read);
  print_ip_addr(buf_read);
  discard_key(buf_read);

  printf(" metric");
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "lsa_type_num"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    printf("%li", val.val);
    val = get_value(buf_read);
  }
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  printf(" %li", val.val);
  if (via)
  {
    printf(" via ");
    int pt = buf_read->pt;
    buf_read->pt = via;
    print_ip_addr(buf_read);
    buf_read->pt = pt;
  }
  if (tag >- 1)
  {
    printf(" tag %08lx", tag);
  }
  val = get_value(buf_read); // end of block
}


void print_lsa_prefix(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  if (val_is_break(val))
    return;
  discard_key(buf_read);
  val = get_value(buf_read); // open block or break
  while (!val_is_break(val))
  {
    val = get_value(buf_read);
    if (compare_buff_str(buf_read, val.val, "stubnet"))
    {
      buf_read->pt+=val.val;
      printf("\t\tstubnet ");
      print_ip_prefix(buf_read);
      discard_key(buf_read);
      val = get_value(buf_read);
      printf(" metric %li", val.val);
    }
    else
    {
      buf_read->pt+=val.val;
      printf("\t\taddress ");
      print_ip_prefix(buf_read);
    }
    printf("\n");
    val = get_value(buf_read);
    val = get_value(buf_read); // open block or break
  }
  val = get_value(buf_read);
  print_ip_addr(buf_read);
}

void print_show_ospf(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  printf("\n");
  if (compare_buff_str(buf_read, val.val, "error"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    printf("error: ");
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    return;
  }
  if (compare_buff_str(buf_read, val.val, "not_implemented"))
  {
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    printf("not implemented: ");
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    return;
  }
  buf_read->pt+=val.val;
  val = get_value(buf_read); // list
  ASSERT(val.major == ARRAY);
  int j = val.val;
  for (int i = 0; i < j; i++)
  {
    val = get_value(buf_read); // open block
    ASSERT(val.major == BLOCK);
    discard_key(buf_read); // dummy id
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    val = get_value(buf_read);
    if (compare_buff_str(buf_read, val.val, "area"))
    {
      buf_read->pt+=val.val;
      printf("area ");
      print_ip_addr(buf_read);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "lsa_router"))
    {
      buf_read->pt+=val.val;
      print_lsa_router(buf_read);
    }
    else if (compare_buff_str(buf_read, val.val, "lsa_network"))
    {
      buf_read->pt+=val.val;
      print_lsa_network(buf_read);
    }
    else if (compare_buff_str(buf_read, val.val, "lsa_sum_net"))
    {
      buf_read->pt+=val.val;
      print_lsa_sum_net(buf_read);
    }
    else if (compare_buff_str(buf_read, val.val, "lsa_sum_rt"))
    {
      buf_read->pt+=val.val;
      print_lsa_sum_rt(buf_read);
    }
    else if (compare_buff_str(buf_read, val.val, "lsa_prefix"))
    {
      buf_read->pt+=val.val;
      print_lsa_prefix(buf_read);
    }
    else if (compare_buff_str(buf_read, val.val, "lsa_external"))
    {
      buf_read->pt+=val.val;
      print_lsa_external(buf_read);
    }
    val = get_value(buf_read);
  }
  discard_key(buf_read);
  val = get_value(buf_read);
  while (!val_is_break(val))
  {
    val = get_value(buf_read);
    if (val_is_break(val))
      return;
    if (compare_buff_str(buf_read, val.val, "other_ABSRs"))
    {
      buf_read->pt+=val.val;
      printf("other ABSRs\n");
      val = get_value(buf_read); // null list
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "router"))
    {
      buf_read->pt+=val.val;
      printf("router ");
      print_ip_addr(buf_read);
      val = get_value(buf_read);
    }
    buf_read->pt+=val.val;
    print_lsa_external(buf_read);
    val = get_value(buf_read);
    val = get_value(buf_read);
  }
}



void print_show_memory(struct buff_reader *buf_read)
{
  printf("BIRD memory usage\n");
  printf("                  Effective   Overhead\n");
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read); // header, may be it should be deleted
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read); // body
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == BLOCK);

  val = get_value(buf_read);
  while (val.major == TEXT && buf_read->pt < buf_read->size)
  {
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    for (unsigned long i = 0; i < strlen("                  ") - val.val; i++)
    {
      putc(' ', stdout);
    }
    buf_read->pt+=val.val;
    val = get_value(buf_read); // block open
    val = get_value(buf_read);
    ASSERT(val.major == TEXT);
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    printf("%7li B  ", val.val);
    val = get_value(buf_read);
    ASSERT(val.major == TEXT);
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    printf("%7li B\n", val.val);
    val = get_value(buf_read);
  }
}

void print_show_status(struct buff_reader *buf_read)
{
  /*
    print("BIRD", answer["show_status:message"]["version"])
        for key in answer["show_status:message"]["body"].keys():
            name = key.replace("_", " ")
            if key == "router_id":
                print(name, self.addr_to_str( answer["show_status:message"]["body"][key]))
            elif key in "server_time last_reboot last_reconfiguration":
                print(name, datetime.datetime.fromtimestamp(answer["show_status:message"]["body"][key]))
            else:
                print(name, answer["show_status:message"]["body"][key])
        print(answer["show_status:message"]["state"])
  */
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  printf("BIRD ");
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == TEXT); // body
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  val = get_value(buf_read);
  ASSERT(val.major == TEXT); // router id
  buf_read->pt+=val.val;
  printf("router id: ");
  print_ip_addr(buf_read);
  printf("\n");
  
  val = get_value(buf_read);
  ASSERT(val.major == TEXT); // hostname
  buf_read->pt+=val.val;
  printf("hostname:  ");
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt+=val.val;

  for (int i =0; i<3; i++)
  {
    val = get_value(buf_read);
    ASSERT(val.major == TEXT); // server time, last rebooot, last reconfiguration
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    buf_read->pt+=val.val;
    printf(":  ");
    val = get_value(buf_read);
    ASSERT(val.major == UINT);
    print_time(val.val);
    printf("\n");
  }
  val = get_value(buf_read);
  if (val.major != TEXT)
    val = get_value(buf_read);
  ASSERT(val.major == TEXT); // state
  printf("state: ");
  buf_read->pt+=val.val;
  val = get_value(buf_read);
  ASSERT(val.major == TEXT);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt+=val.val;
}

void print_show_symbols(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  discard_key(buf_read);
  val = get_value(buf_read);
  int one_item = 0;
  if (val.val == 1)
    one_item = 1;
  if (val.val == 0)
    return;
  val = get_value(buf_read);
  if (val_is_break(val))
  {
    printf("no names found\n");
    return;
  }
  val = get_value(buf_read);
  while (val.major == TEXT)
  {
    buf_read->pt+=val.val; //name
    val = get_value(buf_read);
    print_with_size_(&buf_read->buff[buf_read->pt], val.val);
    for (int i = val.val; i < 15; i++)
    {
      printf(" ");
    }
    buf_read->pt+=val.val;
    val = get_value(buf_read); //type
    buf_read->pt+=val.val;
    val = get_value(buf_read);
    print_with_size_(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    buf_read->pt+=val.val;
    if (one_item)
      return;
    val = get_value(buf_read);
    if (val_is_break(val))
      return;
    val = get_value(buf_read);
  }
}

void print_channel_show_limit(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  int siz = val.val;
  buf_read->pt += val.val;
  val = get_value(buf_read); //block
  val = get_value(buf_read);
  if (val_is_break(val))
    return;
  buf_read->pt += val.val;
  printf("    ");
  print_with_size(&buf_read->buff[buf_read->pt], siz);
  for(int i = 0; i < 16 - siz; i++)
    putc(' ', stdout);
  val = get_value(buf_read);
  printf("%ld ", val.val);
  val = get_value(buf_read);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  buf_read->pt += val.val;
  printf("\n      Action:       ");
  val = get_value(buf_read);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  val = get_value(buf_read);
}

void print_route_change_line(struct buff_reader *buf_read)
{
  for (int i = 0; i < 5; i++)
  {
    struct value val = get_value(buf_read);
    if (val.major == UINT)
      printf(" %10lu", val.val);
    else
      printf("        ---");
  }
  printf("\n");
}

void print_pipe_show_stats(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); //open block
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("  Routes:         %lu imported, ", val.val);
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("%lu exported\n", val.val);
  printf("  Route change stats:     received   rejected   filtered    ignored   accepted\n");
  discard_key(buf_read); //import_updates
  val = get_value(buf_read); //open list
  printf("    Import updates:    ");
  print_route_change_line(buf_read);
  discard_key(buf_read);
  val = get_value(buf_read); //open list
  printf("    Import withdraws:  ");
  print_route_change_line(buf_read);
  discard_key(buf_read);
  val = get_value(buf_read); //open list
  printf("    Export updates:    ");
  print_route_change_line(buf_read);
  discard_key(buf_read);
  val = get_value(buf_read); //open list
  printf("    Export withdraws:  ");
  print_route_change_line(buf_read);
  val = get_value(buf_read); //close block
}

void print_show_protocols_rpki(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); //open block
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("  Cache server:     ");
  print_with_size_(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt += val.val;
  if (compare_buff_str(buf_read, val.val, "cache_port"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("  Cache port:       %lu\n", val.val);
    val = get_value(buf_read);
  }

  print_string_string(buf_read, "  Status:           ");
  print_string_string(buf_read, "  Transport:        ");

  discard_key(buf_read);
  val = get_value(buf_read);
  printf("  Protocol version: %lu\n", val.val);

  discard_key(buf_read);
  printf("  Session ID:       ");
  val = get_value(buf_read);
  if (val.major == TEXT)
  {
    printf("---\n");
    buf_read->pt += val.val;
  }
  else
    printf("%lu\n", val.val);

  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "serial_num"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("  Serial number:    %lu\n", val.val);
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("  Last update:      before %lu s\n", val.val);
  }
  else
  {
    printf("  Serial number:    ---\n");
    printf("  Last update:      ---\n");
  }
  val = get_value(buf_read);
}

void print_channel_show_stats(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); //open block
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("    Routes:         %lu imported, ", val.val);
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "serial_num"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("%lu filtered, ", val.val);
    val = get_value(buf_read);
  }
  buf_read->pt += val.val;
  val = get_value(buf_read);
  printf("%lu exported, ", val.val);
  discard_key(buf_read);
  val = get_value(buf_read);
  printf("%lu preferred\n", val.val);

  printf("    Route change stats:     received   rejected   filtered    ignored   accepted\n");
  discard_key(buf_read); //import_updates
  val = get_value(buf_read); //open list
  printf("      Import updates:     ");
  print_route_change_line(buf_read);

  discard_key(buf_read); //import_updates
  val = get_value(buf_read); //open list
  printf("      Import withdraws:   ");
  print_route_change_line(buf_read);

  discard_key(buf_read); //import_updates
  val = get_value(buf_read); //open list
  printf("      Export updates:     ");
  print_route_change_line(buf_read);

  discard_key(buf_read); //import_updates
  val = get_value(buf_read); //open list
  printf("      Export withdraws:   ");
  print_route_change_line(buf_read);

  val = get_value(buf_read); //close block
}

void print_channel_show_info(struct buff_reader *buf_read)
{
  print_string_string(buf_read, "  Channel ");

  print_string_string(buf_read, "    State:          ");

  print_string_string(buf_read, "    Table:          ");

  discard_key(buf_read);
  struct value val = get_value(buf_read);
  printf("    Preference:     %ld\n", val.val);

  print_string_string(buf_read, "    Input filter:   ");

  print_string_string(buf_read, "    Output filter:  ");

  int pt = buf_read->pt;
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "gr_pending"))
  {
    buf_read->pt += val.val;
    printf("    GR recovery:   ");
    val = get_value(buf_read);
    if (val.val)
      printf(" pending");
    discard_key(buf_read);
    val = get_value(buf_read);
    if (val.val)
      printf(" waiting");
    printf("\n");
  }
  else
  {
    buf_read->pt = pt; // this is not nice, but we need the name of the block.
    //If the name of the block is allways same, we would need to create lists for limits.
  }
  print_channel_show_limit(buf_read);
  print_channel_show_limit(buf_read);
  print_channel_show_limit(buf_read);

  val = get_value(buf_read);
  if (!val_is_break(val))
  {
    buf_read->pt += val.val;
    print_channel_show_stats(buf_read);
    val = get_value(buf_read);
  }
}

void print_bgp_show_afis(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); //open list
  val = get_value(buf_read); //open block (or break)
  while (!val_is_break(val))
  {
    val = get_value(buf_read); //key
    if (compare_buff_str(buf_read, val.val, "name"))
    {
      buf_read->pt += val.val;
      printf(" ");
      val = get_value(buf_read);
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf("\n");
      buf_read->pt += val.val;
    }
    else
    {
      buf_read->pt += val.val;
      val = get_value(buf_read);
      printf(" <%lu/", val.val);
      discard_key(buf_read);
      val = get_value(buf_read);
      printf("%lu>\n", val.val);
    }
    
    val = get_value(buf_read); //close block
    val = get_value(buf_read); //close list or open block
  }
  
}

void print_bgp_capabilities(struct buff_reader *buf_read)
{
  printf("<debug capabilities <%s>, %x %x>\n", &buf_read->buff[buf_read->pt], buf_read->buff[buf_read->pt], buf_read->buff[buf_read->pt+1]);
  discard_key(buf_read);
  struct value val = get_value(buf_read); //open block
  printf("<debug: val major %i, val val %li>\n", val.major, val.val);
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "AF_announced"))
  {
    buf_read->pt += val.val;
    printf("      Multiprotocol\n");
    printf("        AF announced:");
    print_bgp_show_afis(buf_read);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "route_refresh"))
  {
    buf_read->pt += val.val;
    printf("      Route refresh\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "IPv6_nexthop"))
  {
    buf_read->pt += val.val;
    printf("      Extended next hop\n");
    printf("        IPv6 nexthop:\n");
    print_bgp_show_afis(buf_read);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "extended_message"))
  {
    buf_read->pt += val.val;
    printf("      Extended message\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "graceful_restart"))
  {
    buf_read->pt += val.val;
    printf("      Graceful restart\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "restart_time"))
  {
    buf_read->pt += val.val;
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("        Restart time: %lu", val.val);
    val = get_value(buf_read);
    if (compare_buff_str(buf_read, val.val, "restart_recovery"))
    {
      buf_read->pt += val.val;
      printf("        Restart recovery\n");
      val = get_value(buf_read); //zero list
      val = get_value(buf_read);
    }
    discard_key(buf_read);
    printf("        AF supported:\n");
    print_bgp_show_afis(buf_read);
    printf("        AF preserved:\n");
    discard_key(buf_read);
    print_bgp_show_afis(buf_read);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "4-octet_AS_numbers"))
  {
    buf_read->pt += val.val;
    printf("      4-octet AS numbers\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "add_path_RX"))
  {
    buf_read->pt += val.val;
    printf("        RX:\n");
    print_bgp_show_afis(buf_read);
    printf("        TX:\n");
    discard_key(buf_read);
    print_bgp_show_afis(buf_read);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "enhanced_refresh"))
  {
    buf_read->pt += val.val;
    printf("      Enhanced refresh\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "long_lived_gr"))
  {
    buf_read->pt += val.val;
    printf("      Long-lived graceful restart\n");
    val = get_value(buf_read); //zero list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "ll_stale_time"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("        LL stale time: %lu\n", val.val);
    discard_key(buf_read);
    printf("        AF supported:\n");
    print_bgp_show_afis(buf_read);
    printf("        AF preserved:\n");
    discard_key(buf_read);
    print_bgp_show_afis(buf_read);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "hostname"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("      Hostname: ");
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "role"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("      Role: ");
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    val = get_value(buf_read);
  }
}

void print_show_protocols_bgp(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); //open block
  discard_key(buf_read);
  printf("  BGP state:          ");
  val = get_value(buf_read);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  printf("\n");
  buf_read->pt += val.val;
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "neighbor_range"))
  {
    buf_read->pt += val.val;
    printf("    Neighbor range:   ");
    print_ip_prefix(buf_read);
    printf("\n");
  }
  else
  {
    buf_read->pt += val.val;
    printf("    Neighbor address: ");
    print_ip_addr(buf_read);
    discard_key(buf_read);
    val = get_value(buf_read);
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    buf_read->pt += val.val;
    printf("\n");
  }
  val = get_value(buf_read);
  if (compare_buff_str(buf_read, val.val, "neighbor_port"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("    Neighbor port:    %lu\n", val.val);
    discard_key(buf_read);
  }
  else
  {
    printf("<debug ");
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("debug >");
    buf_read->pt += val.val;
  }
  val = get_value(buf_read);
  printf("<debug maj %i val %li>\n", val.major, val.val);
  for (int i = 0; i< 30; i++)
    {
    printf("<debug capabilities %x>\n", buf_read->buff[buf_read->pt+i]);
    }

  printf("    Neighbor AS:      %lu\n", val.val);
  //discard_key(buf_read);
  printf("<debug");
  val = get_value(buf_read);
  printf("  maj %i val %li>\n  ", val.major, val.val);
  print_with_size(&buf_read->buff[buf_read->pt], val.val);
  buf_read->pt += val.val;
  printf("  debug>\n");
  val = get_value(buf_read);
  printf("<debug maj %i val %li>\n", val.major, val.val);
  printf("    Local AS:         %lu\n", val.val);

  val = get_value(buf_read);
  printf("<debug maj %i val %li>\n", val.major, val.val);
  if (compare_buff_str(buf_read, val.val, "gr_active"))
  {
    printf("    Neighbor graceful restart active\n");
    buf_read->pt += val.val;
    val = get_value(buf_read); //null list
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "error_wait_remains"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("    Error wait:       %lu/", val.val);
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("%lu\n", val.val);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "connect_remains"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("    Connect delay:    %lu/", val.val);
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("%lu\n", val.val);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "connect_remains"))
  {
    buf_read->pt += val.val;
    val = get_value(buf_read);
    printf("    Connect delay:    %lu/-\n", val.val);
    val = get_value(buf_read);
  }
  if (compare_buff_str(buf_read, val.val, "neighbor_id"))
  {
    buf_read->pt += val.val;
    printf("    Neighbor ID:      ");
    printf("<debug capabilities <%s>, %x %x>\n", &buf_read->buff[buf_read->pt], buf_read->buff[buf_read->pt], buf_read->buff[buf_read->pt+1]);
    for (int i = 0; i< 30; i++)
    {
    printf("<debug capabilities %x>\n", buf_read->buff[buf_read->pt+i]);
    }
    print_ip_addr(buf_read);
    printf("\n");
    printf("    Local capabilities\n");
    print_bgp_capabilities(buf_read);
    printf("    Neighbor capabilities\n");
    print_bgp_capabilities(buf_read);
    discard_key(buf_read);
    printf("    Session:          ");
    val = get_value(buf_read); //open list
    val = get_value(buf_read);
    while (!val_is_break(val))
    {
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf(" ");
      buf_read->pt += val.val;
      val = get_value(buf_read);
    }
    printf("\n");
    discard_key(buf_read);
    printf("    Source address:   ");
    print_ip_addr(buf_read);
    printf("\n");

    discard_key(buf_read);
    val = get_value(buf_read);
    printf("    Hold timer:       ");
    print_as_time(val.val);
    printf("/");
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("%lu\n", val.val);

    discard_key(buf_read);
    val = get_value(buf_read);
    printf("    Keepalive timer:  ");
    print_as_time(val.val);
    printf("/");
    discard_key(buf_read);
    val = get_value(buf_read);
    printf("%lu\n", val.val);
  }
  if (compare_buff_str(buf_read, val.val, "last_err1"))
  {
    buf_read->pt += val.val;
    printf("    Last error:       ");
    discard_key(buf_read);
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf(" ");
    discard_key(buf_read);
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    printf("\n");
    val = get_value(buf_read);
  }

  discard_key(buf_read); //channels
  val = get_value(buf_read); //open list
  val = get_value(buf_read); //open block
  while (!val_is_break(val))
  {
    discard_key(buf_read); //channel
    val = get_value(buf_read); //open block

    print_channel_show_info(buf_read);
    val = get_value(buf_read);
    if (compare_buff_str(buf_read, val.val, "neighbor_gr"))
    {
      buf_read->pt += val.val;
      printf("    Neighbor GR:    ");
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "llstale_timer"))
    {
      buf_read->pt += val.val;
      val = get_value(buf_read);
      printf("    LL stale timer: ");
      print_as_time(val.val);
      printf("/-");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "next_hop"))
    {
      buf_read->pt += val.val;
      printf("    BGP Next hop:   ");
      print_ip_addr(buf_read);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "next_hop1"))
    {
      buf_read->pt += val.val;
      printf("    BGP Next hop:   ");
      print_ip_addr(buf_read);
      discard_key(buf_read);
      printf(" ");
      print_ip_addr(buf_read);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "igp_ipv4_table"))
    {
      buf_read->pt += val.val;
      val = get_value(buf_read);
      printf("    IGP IPv4 table: ");
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "igp_ipv4_table"))
    {
      buf_read->pt += val.val;
      printf("    IGP IPv6 table: ");
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf("\n");
      val = get_value(buf_read);
    }
    if (compare_buff_str(buf_read, val.val, "igp_ipv4_table"))
    {
      buf_read->pt += val.val;
      printf("    Base table:     ");
      print_with_size(&buf_read->buff[buf_read->pt], val.val);
      printf("\n");
      val = get_value(buf_read);
    }
    val = get_value(buf_read);
  }
  val = get_value(buf_read);
  printf("<debug: val major %i, val val %li>\n", val.major, val.val);
}

void print_show_protocols(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read);
  ASSERT(val.major == BLOCK);
  discard_key(buf_read); //table
  val = get_value(buf_read);
  ASSERT(val.major == ARRAY);
  val = get_value(buf_read);
  printf("%-10s %-10s %-10s %-6s %-18s  %s\n",
	    "Name", "Proto", "Table", "State", "Since", "Info");
  while (!val_is_break(val))
  {
    ASSERT(val.major == BLOCK);
    discard_key(buf_read); //name
    val = get_value(buf_read);
    print_with_size_add_space(&buf_read->buff[buf_read->pt], val.val, 11);
    buf_read->pt += val.val;
    discard_key(buf_read); //proto
    val = get_value(buf_read);
    print_with_size_add_space(&buf_read->buff[buf_read->pt], val.val, 11);
    buf_read->pt += val.val;
    discard_key(buf_read); //table
    val = get_value(buf_read);
    print_with_size_add_space(&buf_read->buff[buf_read->pt], val.val, 11);
    buf_read->pt += val.val;
    discard_key(buf_read); //state
    val = get_value(buf_read);
    print_with_size_add_space(&buf_read->buff[buf_read->pt], val.val, 7);
    buf_read->pt += val.val;
    discard_key(buf_read); // since
    val = get_value(buf_read);
    print_time(val.val);
    printf(" ");
    discard_key(buf_read); //info
    val = get_value(buf_read);
    print_with_size(&buf_read->buff[buf_read->pt], val.val);
    buf_read->pt += val.val;
    printf("\n");

    val = get_value(buf_read);
    if (!val_is_break(val))
    {
      if (compare_buff_str(buf_read, val.val, "description"))
      {
        buf_read->pt += val.val;
        val = get_value(buf_read);
        printf("  Description:    ");
        print_with_size(&buf_read->buff[buf_read->pt], val.val);
        printf("\n");
        buf_read->pt += val.val;
        val = get_value(buf_read);
      }
      if (compare_buff_str(buf_read, val.val, "message"))
      {
        buf_read->pt += val.val;
        val = get_value(buf_read);
        printf("  Message:        ");
        print_with_size(&buf_read->buff[buf_read->pt], val.val);
        printf("\n");
        buf_read->pt += val.val;
        val = get_value(buf_read);
      }
      if (compare_buff_str(buf_read, val.val, "router_id"))
      {
        buf_read->pt += val.val;
        printf("  Router ID:      ");
        print_ip_addr(buf_read);
        val = get_value(buf_read);
      }
      if (compare_buff_str(buf_read, val.val, "vfr"))
      {
        buf_read->pt += val.val;
        val = get_value(buf_read);
        printf("  VRF:            ");
        print_with_size(&buf_read->buff[buf_read->pt], val.val);
        printf("\n");
        buf_read->pt += val.val;
        val = get_value(buf_read);
      }
      if (val_is_break(val))
      {
        return;
      }
      ASSERT(val.major == TEXT);

      if (compare_buff_str(buf_read, val.val, "rpki"))
      {
        buf_read->pt += val.val;
        print_show_protocols_rpki(buf_read);
        printf("\n");
      }
      else if (compare_buff_str(buf_read, val.val, "pipe"))
      {
        buf_read->pt += val.val;
        val = get_value(buf_read); //open block
        printf("  Channel %s\n", "main");
        print_string_string(buf_read, "    Table:          ");
        print_string_string(buf_read, "    Peer table:     ");
        print_string_string(buf_read, "    Table:          ");
        print_string_string(buf_read, "    Import state:   ");
        print_string_string(buf_read, "    Export state:   ");
        print_string_string(buf_read, "    Import filter:  ");
        print_string_string(buf_read, "    Export filter:  ");
        print_channel_show_limit(buf_read);
        print_channel_show_limit(buf_read);
        val = get_value(buf_read);
        if (!val_is_break(val))
        {
          buf_read->pt += val.val; // discarding key "stats"
          print_pipe_show_stats(buf_read);
          val = get_value(buf_read);
        }
        printf("\n");
      }
      else if (compare_buff_str(buf_read, val.val, "bgp"))
      {
        buf_read->pt += val.val;
        print_show_protocols_bgp(buf_read);
        val = get_value(buf_read);
        printf("<debug: val major %i, val val %li>\n", val.major, val.val);
        printf("\n");
      }
      else
      {
        buf_read->pt += val.val;
        val = get_value(buf_read);
        while(!val_is_break(val))
        {
          print_channel_show_info(buf_read);
          val = get_value(buf_read);
          if (val.major == TEXT)
          {
            buf_read->pt += val.val;
            val = get_value(buf_read);
          }
        }
        printf("\n");
      }
    }
    val = get_value(buf_read);
    printf("<debug: val major %i, val val %li>\n", val.major, val.val);
  }
}

void print_cbor_response(byte *cbor, int len)
{
  //
  FILE *write_ptr;

  write_ptr = fopen("arrived.cbor", "wb");

  fwrite(cbor, len, 1, write_ptr);
  fclose(write_ptr);
  //
  struct buff_reader buf_read;
  buf_read.buff = cbor;
  buf_read.size = len;
  buf_read.pt = 0;
  struct value val = get_value(&buf_read);
  ASSERT(val.major == BLOCK);
  ASSERT(val.val <=1);
  val = get_value(&buf_read);
  ASSERT(val.major == TEXT);
  printf("\n");

  if (compare_buff_str(&buf_read, val.val, "show_memory:message"))
  {
    buf_read.pt += val.val;
    print_show_memory(&buf_read);
  }
  else if (compare_buff_str(&buf_read, val.val, "show_status:message"))
  {
    buf_read.pt += val.val;
    print_show_status(&buf_read);
  }
  else if (compare_buff_str(&buf_read, val.val, "show_symbols:message"))
  {
    buf_read.pt += val.val;
    print_show_symbols(&buf_read);
  }
  else if (compare_buff_str(&buf_read, val.val, "show_ospf:message"))
  {
    buf_read.pt += val.val;
    print_show_ospf(&buf_read);
  }
  else if (compare_buff_str(&buf_read, val.val, "show_protocols:message"))
  {
    buf_read.pt += val.val;
    print_show_protocols(&buf_read);
  }
  printf("\nbird>");
  fflush(stdout);
}

