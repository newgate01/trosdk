# trosdk


```shell
docker build -t protoc:laster .
```



```shell

docker run -it -rm -v "${PWD}":/src -d protoc:laster \
protoc -I . -I api \
--go_opt=paths=source_relative \
--go-grpc_opt=paths=source_relative \
--go_out=. --go-grpc_out=:. ./api/*.proto
```


```shell

docker run -it --rm -v "${PWD}":/src -d protoc:laster \
protoc -I . -I core \
--go_opt=paths=source_relative \
--go-grpc_opt=paths=source_relative \
--go_out=. --go-grpc_out=:. ./core/*.proto
```


```shell

docker run -it --rm -v "${PWD}":/src -d protoc:laster \
protoc -I . -I core/contract \
--go_opt=paths=source_relative \
--go-grpc_opt=paths=source_relative \
--go_out=. --go-grpc_out=:. ./core/contract/*.proto
```

```shell

docker run -it --rm -v "${PWD}":/src -d protoc:laster \
protoc -I . -I core/contract \
--go_opt=paths=source_relative \
--go-grpc_opt=paths=source_relative \
--go_out=. --go-grpc_out=:. ./core/contract/*.proto
```

```shell

docker run -it --rm -v "${PWD}":/src -d protoc:laster \
protoc -I . -I google/api \
--go_opt=paths=source_relative \
--go-grpc_opt=paths=source_relative \
--go_out=. --go-grpc_out=:. ./google/api/*.proto
```

