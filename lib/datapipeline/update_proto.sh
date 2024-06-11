###############################################################################
# update protobuf c files based on new opensync stats protobuf description
###############################################################################

RELDIR=$(basename $(dirname $PWD))/$(basename $PWD)

if [ $RELDIR != "lib/datapipeline" ]
then
    echo "Please cd to src/lib/datapipeline folder"
    exit 1
fi

FNAME=opensync_stats
protoc-c --c_out=. --proto_path=../../../interfaces ../../../interfaces/${FNAME}.proto
mv "${FNAME}.pb-c.c" src/
mv "${FNAME}.pb-c.h" inc/

if [ $? -ne 0 ]
then
    echo "Error generating protobuf c files"
else
    echo "protobuf update successfully completed"
fi
