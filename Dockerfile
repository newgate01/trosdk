FROM golang:1.22.6

WORKDIR /src

RUN apt-get update
RUN apt install -y protobuf-compiler
RUN protoc --version
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

CMD ["bash"]

