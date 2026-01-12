FROM scratch AS dataplane
ADD ./dataplane.tar /
CMD [ "/bin/dataplane" ]

FROM dataplane as dataplane-debug
ADD ./gdbserver.tar /
ENTRYPOINT [ "/bin/gdbserver", "--no-startup-with-shell", "127.0.0.99:9999" ]
