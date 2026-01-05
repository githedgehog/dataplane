ARG BASE=scratch
FROM $BASE
ADD ./dataplane.tar /
ENTRYPOINT [ "/bin/dataplane" ]
