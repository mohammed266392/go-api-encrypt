FROM golang:1.24.5-alpine3.22

COPY main_exec ./main_exec

EXPOSE 8080

ENTRYPOINT ["./main_exec"]