#!/usr/bin/env bash

while (( $# ))
do
    case "$1" in

        (--help | -h)
          echo 'help' 
            exit 0
        ;;
    esac
done
