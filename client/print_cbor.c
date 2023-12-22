#include <time.h>
#include "nest/cbor_parse.c"

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

void print_with_size_(byte *string, int len)
{
  for (int i = 0; i < len; i++)
  {
    putc(string[i], stdout);
  }
}

void print_ip_addr(struct buff_reader *buf_read)
{
  struct value val = get_value(buf_read); // tag
  val = get_value(buf_read); // bytestring
  for (int i = 0; i < val.val-1; i++)
  {
    printf("%i.", buf_read->buff[buf_read->pt + i]);
  }
  printf("%i", buf_read->buff[buf_read->pt + val.val]);
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

void print_cbor_response(byte *cbor, int len)
{
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
  printf("\nbird>");
  fflush(stdout);
}





