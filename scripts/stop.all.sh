NODE_PID=.node.pid
DESIGNATOR_PID=.designator.pid

kill `cat $PWD/$DESIGNATOR_PID`
kill `cat $PWD/$NODE_PID`
