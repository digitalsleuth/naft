#!/bin/bash

set -x

DISTRO=$1
docker run -it --rm --name="naft-test-${DISTRO}" -v `pwd`/naft:/naft --cap-add SYS_ADMIN digitalsleuth/naft-tester:${DISTRO} /bin/bash
