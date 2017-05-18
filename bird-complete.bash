#!/bin/bash

function _bird_complete {
  CMD=$1
  NOW=$2
  PREV=$3

  case $PREV in
    -c|-D|-P|-s)
      COMPREPLY=( $(compgen -f -- $NOW) )
      ;;
    -g)
      COMPREPLY=( $(compgen -g -- $NOW) )
      ;;
    -u)
      COMPREPLY=( $(compgen -u -- $NOW) )
      ;;
    *)
      COMPREPLY=( $(compgen -W '-c -d -D -f -g -h -l -p -P -R -s -u --help --version' -- $NOW) )
      ;;
  esac
}

function _birdc_complete {
  CMD=$1
  NOW=$2
  PREV=$3

  case $PREV in
    -*([lvr])s)
      COMPREPLY=( $(compgen -W "$(find -maxdepth 1 -type s)" -- $NOW) )
      return
      ;;
  esac
  
  case $NOW in
    -*([lvr])s)
      COMPREPLY=( $(compgen -W "$(find -maxdepth 1 -type s | sed 's#^#'$NOW'#') ${NOW}l ${NOW}r ${NOW}v" -- $NOW) )
      return
      ;;
    -*)
      COMPREPLY=( $(compgen -W "${NOW}l ${NOW}v ${NOW}r ${NOW}s") )
      return
      ;;
  esac

  COMPREPLY=( $($CMD -C "$NOW" "$COMP_TYPE" "$COMP_CWORD" "${COMP_WORDS[@]}") )
}

complete -F _bird_complete bird
complete -F _birdc_complete birdc
complete -F _birdc_complete birdcl
