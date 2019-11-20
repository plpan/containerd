#!/bin/bash

cmd=$1

if [ "$cmd" == "f" ]; then
	if [ -f /bin/docker-containerd.bak ]; then
		exit -1
	fi
	mv /bin/docker-containerd /bin/docker-containerd.bak
	mv /bin/docker-containerd-ctr /bin/docker-containerd-ctr.bak
	mv /bin/docker-containerd-shim /bin/docker-containerd-shim.bak
	cp /home/odin/panpeilong/go/src/github.com/docker/containerd/bin/containerd /bin/docker-containerd
	cp /home/odin/panpeilong/go/src/github.com/docker/containerd/bin/ctr /bin/docker-containerd-ctr
	cp /home/odin/panpeilong/go/src/github.com/docker/containerd/bin/containerd-shim /bin/docker-containerd-shim
	systemctl restart docker
elif [ "$cmd" == "b" ]; then
	if ! [ -f /bin/docker-containerd.bak ]; then
		exit -1
	fi
	mv /bin/docker-containerd.bak /bin/docker-containerd
	mv /bin/docker-containerd-ctr.bak /bin/docker-containerd-ctr
	mv /bin/docker-containerd-shim.bak /bin/docker-containerd-shim
	systemctl restart docker
fi
