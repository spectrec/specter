CURRENT_DIR=$PWD

DESIGNATOR_PID=.designator.pid
NODE_PID=.node.pid

perl designator.plx &
echo $! > $CURRENT_DIR/$DESIGNATOR_PID

sleep 1

cd ..
./specter &
echo $! > $CURRENT_DIR/$NODE_PID
cd $CURRENT_DIR

echo done
