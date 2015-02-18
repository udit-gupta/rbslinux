#!/bin/bash

# User-Space Utility to add and delete roles for role based file system access control.
# 1. Two roles are present in current verison: Admin(0) and Non-admin(1).
# 2. Both Roles have some implicit inode permissions.
#       A) Admin can create files and directories, remove them and rename them.
#       B) Non-Admin can neither create files/directories nor they can remove/rename them. 


#Configuration Options

CONFIG_FILE="/etc/rbslinux.conf"
CONFIG_FILE_DLIM=" "

USER_DB="/etc/passwd"
USER_DB_DLIM=":"

MIN_VALID_UID=1000

ADMIN_ID=0
NON_ADMIN_ID=1

# Utility Functions

usage() { 
    echo "Usage: $0 [-p] [-i <admin uid>] [-a <non-admin uid>] [-u <admin username>] [-v <non-admin username>]" 1>&2; 
    exit 1; 
}

#Parse Comman-line Arguments

while getopts pi:a:u:v: opt; do
  case $opt in
  p)
        echo "Repopulating the whole RBS database with default values .. "
        
        cut -d"$USER_DB_DLIM" -f1 $USER_DB > rbs_usernames.sh
        cut -d"$USER_DB_DLIM" -f3 $USER_DB > rbs_uids.sh

        paste -d"$CONFIG_FILE_DLIM" rbs_usernames.sh rbs_uids.sh > tmp_rbs.conf

        number=$(wc -l tmp_rbs.conf | cut -d' ' -f1)

        i=1
        while [[ $i -le $number ]]; do
            echo -e "0" >> tmp_file
            i=$(($i + 1))
        done

        paste -d"$CONFIG_FILE_DLIM" tmp_rbs.conf tmp_file > tmprbs.conf
        awk -v min_uid=$MIN_VALID_UID 'int($2) >= min_uid' tmprbs.conf > $CONFIG_FILE

        #Remove Temporaries 
        rm rbs_usernames.sh rbs_uids.sh tmp_file tmp_rbs.conf tmprbs.conf
      
      ;;
  i)
      rbs_uid=$OPTARG
      echo "Role for UID: $rbs_uid has been changed to Admin."
      awk -v var="$rbs_uid" -v admin_id=$ADMIN_ID '{ if ($2 == var) $3=admin_id; print $0 }' $CONFIG_FILE > tmp_rbs.conf
      mv tmp_rbs.conf $CONFIG_FILE
      ;;
  a)
      rbs_uid=$OPTARG
      echo "Role for UID: $rbs_uid has been changed to Non-admin."
      awk -v var="$rbs_uid"  -v non_admin_id=$NON_ADMIN_ID '{ if ($2 == var) $3=non_admin_id; print $0 }' $CONFIG_FILE> tmp_rbs.conf
      mv tmp_rbs.conf $CONFIG_FILE
      ;;
  u)
      rbs_uname=$OPTARG
      echo "Role for USER: $rbs_uname has been changed to Admin."
      awk -v var="$rbs_uname"  -v admin_id=$ADMIN_ID '{ if ($1 == var) $3=admin_id; print $0 }' $CONFIG_FILE> tmp_rbs.conf
      mv tmp_rbs.conf $CONFIG_FILE
      ;;
  v)
      rbs_uname=$OPTARG
      echo "Role for USER: $rbs_uname has been changed to Non-admin."
      awk -v var="$rbs_uname" -v non_admin_id=$NON_ADMIN_ID '{ if ($1 == var) $3=non_admin_id; print $0 }' $CONFIG_FILE> tmp_rbs.conf
      mv tmp_rbs.conf $CONFIG_FILE
      ;;
  *)
      usage
      ;;
  esac
done

#By Default, Show Usage Options 
if [ -z "$1" ]; then
       usage
fi

