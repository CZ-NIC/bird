-- Based on a sample custom reader that just parses text into blankline-separated
-- paragraphs with space-separated words.
--
-- Source: https://pandoc.org/custom-readers.html

-- Debug logs
local logging = require 'tools/logging'

-- For better performance we put these functions in local variables:
local P, S, R, Cf, Cc, Ct, V, Cs, Cg, Cb, B, C, Cmt =
  lpeg.P, lpeg.S, lpeg.R, lpeg.Cf, lpeg.Cc, lpeg.Ct, lpeg.V,
  lpeg.Cs, lpeg.Cg, lpeg.Cb, lpeg.B, lpeg.C, lpeg.Cmt

local whitespacechar = S(" \t\r\n")
local wordchar = (1 - whitespacechar)
local spacechar = S(" \t")
local newline = P"\r"^-1 * P"\n"

local blankchar = S(" \t\r\n")
local blankmore = blankchar^0

local entitytab = {
  lt = "<";
  gt = ">";
  ndash = "–";
  tilde = "~";
  amp = "&";
  verbar = "|";
}
local entity = P"&" * C(P(1 - S"&;")^1) * P";" / function (t)
  local e = entitytab[t]
  if e == nil then return "!!ENTITY-" .. t .. "-ENTITY!!" else return e end
end

local inelement = blankmore * Ct((entity + C(1 - P"<"))^0) / function (t)
  if #t == 0 then return "" end
  while t[#t]:match("%s") do t[#t] = nil end -- strip trailing whitespace
  return table.concat(t, "")
end

local ininline = Ct((entity + C(1 - P"/"))^0) / function (t)
  if #t == 0 then return "" end
  return table.concat(t, "")
end

function mergetables(t)
--  logging.temp("merging", #t)
  local n = {}
  local v, q
  for _, v in ipairs(t) do
    if pandoc.utils.type(v) == "table" then
--      logging.temp("is table", #v)
      for _, q in ipairs(v) do
	table.insert(n, q)
      end
    elseif pandoc.utils.type(v) == "Inline" and v.text == "" then
      -- ignore this
    else
--      logging.temp("direct", v, pandoc.utils.type(v), "x", v.text, "x")
      table.insert(n, v)
    end
  end
--  logging.temp("returning", #n)
  return n
end

-- Grammar
G = P{ "Pandoc",
  Pandoc = P"<!doctype birddoc system>" * V"BIRDDoc" / function (t)
    doc = {}
    meta = {}
    for _, v in ipairs(t) do
      -- Split out meta blocks
      if pandoc.utils.type(v) == "Meta" then
	for mk,mv in pairs(v) do
	  meta[mk] = mv
	end
      else
	table.insert(doc, v)
      end
    end
--    logging.temp('pandoc', t[1], t[2][2], t[3])
    return pandoc.Pandoc(doc, meta)
  end;

  BIRDDoc = Ct((blankchar + V"Comment" + V"Book")^1) / mergetables;

  CommentInside = (1 - P"-->") / pandoc.Str;
  Comment = P"<!--" * Ct(V"CommentInside"^1) * P"-->" / function (t)
--    logging.temp("COMMENT", t)
    return pandoc.Str("")
  end;

  BookInside = V"Comment" + V"BookIgnored" + V"Title" + V"Author" + V"Abstract" + V"Chapter" + blankchar + V"ParseFail";
  BookIgnored = P"<toc>";
  Book = P"<book>" * Ct(V"BookInside"^1) * P"</book>" / mergetables;

  Title = P"<title>" * inelement / function (t)
    return {
      pandoc.Meta({ title = t });
--      pandoc.Header(1, t);
    } end;

  Author = P"<author>" * blankmore * Ct((V"AuthorOne")^1) * blankmore * P"</author>" / function (t)
    return pandoc.Meta({ author = t })
  end;
  AuthorOne = inelement * P"<it/&lt;" * C((1 - S"&")^1) * P("&gt;/") * P(",")^0 / function (n, e)
--    return { name = n; email = e; }
    return n .. " <" .. e .. ">"
  end;

  Abstract = P"<abstract>" * inelement * P"</abstract>" / function (t)
    return {
      pandoc.Meta({ abstract = t });
--      pandoc.Emph(t);
    }
  end;

  Chapter = P"<chapt>" * inelement * V"Label" * Ct(V"ChapterInside"^1) / function (name, label, inside)
--    logging.temp("chapt", name, label)
    return mergetables({
      pandoc.Header(1, name, { id = label });
      mergetables(inside);
    })
  end;
  ChapterInside = V"Sect" + blankchar;

  Sect = P"<sect>" * inelement * V"Label" * Ct(V"SectInside"^0) / function (name, label, inside)
--    logging.temp("sect", name, label, #inside)
    return mergetables({
      pandoc.Header(2, name, { id = label });
      mergetables(inside);
    })
  end;
  SectInside =
    V"Sect1" +
    V"Sect1Inside";

  Sect1 = P"<sect1>" * inelement * V"Label" * Ct((V"Sect1Inside" - P"<sect1>")^0) / function (name, label, inside)
    return mergetables({
      pandoc.Header(3, name, { id = label });
      mergetables(inside);
    })
  end;
  Sect1Inside =
    V"Sect2" +
    V"Sect2Inside";

  Sect2 = P"<sect2>" * inelement * V"Label" * Ct((V"Sect2Inside" - P"<sect1>" - P"<sect2>")^0) / function (name, label, inside)
    return mergetables({
      pandoc.Header(4, name, { id = label });
      mergetables(inside);
    })
  end;
  Sect2Inside =
    V"Sect3" +
    V"Sect3Inside";

  Sect3 = P"<sect3>" * inelement * V"Label" * Ct((V"Sect3Inside" - P"<sect1>" - P"<sect2>" - P"<sect3>")^0) / function (name, label, inside)
    return mergetables({
      pandoc.Header(5, name, { id = label });
      mergetables(inside);
    })
  end;
  Sect3Inside =
    V"Para" +
    V"ItemList" +
    V"DescripList" +
    V"CodeBlock" +
    V"TableBlock" +
    blankchar + V"ParseFail";

  Para = P"<p>" * Ct(V"InPara") * P"</p>"^-1 / function (t)
--    logging.temp("para", #t)
    return pandoc.Para(mergetables(t))
  end;

  InParaItems =
      V"Emph" +
      V"Bold" +
      V"It" +
      V"HTMLURL" +
      V"InlineCodeLong" +
      V"InlineCodeShort" +
      V"InlineCodeIt" +
      V"InlineCodeItLong" +
      V"InlineConfLong" +
      V"InlineConfShort" +
      V"FilePathLong" +
      V"FilePathShort" +
      V"RFCRef" +
      V"InternalRef" +
      V"Comment" +
      (V"Label" / function (e) return pandoc.Span({}, { id = e }) end);

  InPara = blankmore * Ct((
      V"InParaItems" +
      entity + C(1 - P"<")
      )^0) * blankmore / function (t)
    buf = {}
    out = {}
    t = mergetables(t)
    if #t > 0 then
      while pandoc.utils.type(t[#t]) == "string"
	and t[#t]:match("%s") do
	t[#t] = nil
      end
    end
    for _,v in ipairs(t) do
      if pandoc.utils.type(v) == "string" then
	table.insert(buf, v)
      else
	if #buf > 0 then
	  table.insert(out, pandoc.Str(table.concat(buf, "")))
	  buf = {}
	end
	table.insert(out, v)
      end
    end
    if #buf > 0 then
      table.insert(out, pandoc.Str(table.concat(buf, "")))
    end
    return out
--      logging.temp("inpara", pandoc.utils.type(v), v) end
  end;

  ParaBreak = C(P"\n\n" + P"<p>");

  InDescrip = blankmore * Ct((
      V"ParaBreak" +
      V"InParaItems" +
      V"CodeBlock" +
      entity + C(1 - P"<")
      )^0) * blankmore / function (t)
    local inlines = {}
    local blocks = {}
    local t = mergetables(t)
--    logging.temp("indescrip in", t)
    if #t > 0 then
      while pandoc.utils.type(t[#t]) == "string"
	and t[#t]:match("%s") do
	t[#t] = nil
      end
    end
    for _,v in ipairs(t) do
      if pandoc.utils.type(v) == "string" then
	if v == "\n\n" or v == "<p>" then
	  if #inlines > 0 then
	    table.insert(blocks, pandoc.Para(inlines))
	    inlines = {}
	  end
	elseif #inlines > 0 or not v:match("^%s+$") then
--	  logging.temp("inserting", v, "inlines", #inlines)
	  table.insert(inlines, pandoc.Str(v))
	end
      elseif pandoc.utils.type(v) == "Inline" then
	table.insert(inlines, v)
      elseif pandoc.utils.type(v) == "Block" then
	if #inlines > 0 then
	  table.insert(blocks, pandoc.Para(inlines))
	  inlines = {}
	end
	table.insert(blocks, v)
      else
	error("unexpected pandoc type " .. pandoc.utils.type(v))
      end
    end
    if #inlines > 0 then
      table.insert(blocks, pandoc.Para(inlines))
    end
--    logging.temp("indescrip out", blocks)
    return blocks
  end;

  Emph = P"<em/" * ininline * P"/" / pandoc.Strong;
  Bold = P"<bf/" * ininline * P"/" / pandoc.Strong;
  It = P"<it/" * ininline * P"/" / pandoc.Emph;
  InlineCodeIt = (P"<m/" + P"<M/") * ininline * P"/" / function (e)
    return pandoc.Emph(e, { class = "code" })
  end;
  InlineCodeItLong = (P"<m>" + P"<M>") * inelement * (P"</m>" + P"</M>") / function (e)
    return pandoc.Emph(e, { class = "code" })
  end;

  HTMLURL = P"<HTMLURL" * Ct((
      P'URL="' * Cg((1 - S'"')^1, "url") * P'"'
    + P'name="' * Cg((1 - S'"')^1, "text") * P'"'
    + blankchar
  )^1) * P">" / function (t)
    return pandoc.Link(t.text, t.url)
  end;

  InternalRef = P"<ref" * Ct((
      P'id="' * Cg((1 - S'"')^1, "url") * P'"'
    + P'name="' * Cg((1 - S'"')^1, "text") * P'"'
    + blankchar
  )^1) * P">" / function (t)
    return pandoc.Link(t.text, "#" .. t.url)
  end;

  RFCRef = P"<rfc" * Ct((
      P'id="' * Cg((1 - S'"')^1, "url") * P'"'
    + blankchar
  )^1) * P">" / function (t)
    -- TODO: create a custom markdown extension for this
    return pandoc.Link("RFC " .. t.url, "https://datatracker.ietf.org/doc/rfc" .. t.url, nil, { class = "rfc" })
  end;

  InlineCodeLong = P'<tt>' * inelement * P'</tt>' / pandoc.Code;
  InlineCodeShort = P'<tt/' * ininline * P'/' / pandoc.Code;
  InlineConfLong = P'<cf>' * V"InPara" * P'</cf>' / function (t)
--    logging.temp("inlineconflong", t)
    buf = {}
    out = {}
    for _,v in ipairs(t) do
      if pandoc.utils.type(v) == "Inline" and v.tag == "Str" then
	table.insert(buf, v.text)
      else
--	logging.temp("got type", pandoc.utils.type(v))
	if #buf > 0 then
	  table.insert(out, pandoc.Code(table.concat(buf, "")))
	  buf = {}
	end
	table.insert(out, v)
      end
    end
    if #buf > 0 then
      table.insert(out, pandoc.Code(table.concat(buf, "")))
    end
--    logging.temp("inlineconflong out", out)
    return out
  end;
  InlineConfShort = P'<cf/' * ininline * P'/' / function (e)
    return pandoc.Code(e, { class = "config" })
  end;
  FilePathLong = P'<file>' * inelement * P'</file>' / function (e)
    return pandoc.Code(e, { class = "filepath" })
  end;
  FilePathShort = P'<file/' * ininline * P'/' / function (e)
    return pandoc.Code(e, { class = "filepath" })
  end;

  Label = P'<label id="' * C((1 - P('"'))^0) * P'">';

  ItemList = P"<itemize>" * Ct((V"ItemListItem" + blankchar)^1) * P"</itemize>" / pandoc.BulletList;
  ItemListItem = P"<item>" * V"InPara";

  DescripList = P"<descrip>" * Ct((V"DescripListItem" + blankchar)^1) * P"</descrip>" / pandoc.DefinitionList;
  DescripListItem = P"<tag>" * V"Label" * V"InPara" * "</tag>" * (V"InDescrip" - P"<tag>" - P"</descrip>") / function (l,t,u)
--    logging.temp("dli", t,u)
    return { pandoc.Span(t, { class = "code", id = l }), { u }}
  end;

  CodeBlock = P'<code>' * C((1 - P'</code>')^0) * P'</code>' / pandoc.CodeBlock;

  TableBlockIgnoreBf = P'<bf/' * ininline * '/';

  -- There is only one table
  TableBlock = P'<table loc="h">' * blankmore * P'<tabular ca="l|l|l|r|r">' * blankmore * Ct((
    P'<hline>' +
    V"TableBlockIgnoreBf" +
    V"InParaItems" +
    entity + C(1 - P'</tabular>')
    )^0) * blankmore * P'</tabular>' * blankmore * P'</table>' / function(t)
      -- in t, the whole string is split by chars
      local row = {}
      local tbody = {}
      local thead = nil
      local finishrow = function(row)
	local cell = {}
	local rowblock = {}
	local finishcell = function(cell)
--	  logging.temp("cell unstripped", cell)
	  while pandoc.utils.type(cell[#cell]) == "string" and
	    cell[#cell]:match("^%s$") do
	    cell[#cell] = nil
	  end
--	  logging.temp("cell from", cell)
	  table.insert(rowblock, pandoc.Cell(pandoc.Para(cell)))
	end

	for _,w in ipairs(row) do
	  if w == "|" then
	    finishcell(cell)
	    cell = {}
	  elseif #cell == 0 and
	    (pandoc.utils.type(w) == "string") and
	    w:match("^%s$") then
--	    logging.temp("ignoring", w)
	  else
	    table.insert(cell, w)
	  end
	end

	finishcell(cell)

--	logging.temp("row from", row, "to", rowblock)
	if thead == nil then
	  thead = pandoc.Row(rowblock)
	else
	  table.insert(tbody, pandoc.Row(rowblock))
	end
      end

      for _,v in ipairs(t) do
	if v == "@" then
	  finishrow(row)
	  row = {}
	else
	  table.insert(row, v)
	end
      end

      finishrow(row)
--      logging.temp("table body", tbody)

      return pandoc.Table(
	{
	  long = "BGP channel variants";
	},
	{
	  { "AlignLeft", 0.60 },
	  { "AlignLeft", 0.60 },
	  { "AlignLeft", 0.60 },
	  { "AlignRight", 0.20 },
	  { "AlignRight", 0.20 },
	},
	pandoc.TableHead({thead}),
	--{ body = tbody },
	{{ body = tbody, attr = pandoc.Attr(), row_head_columns = 0, head = {} }},
	pandoc.TableFoot()
      )
  end;

  ParseFail = (1 - P"<sect>" - P"<chapt>" - P"</book>") / function (t) return pandoc.CodeBlock("PARSER FAILED " .. t) end;
}

function Reader(input)
  return lpeg.match(G, tostring(input))
end
