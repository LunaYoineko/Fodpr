FROM nimlang/nim:latest

WORKDIR /app

COPY . /app/fodpr

WORKDIR /app/fodpr

# nim-lmdb は実行時に liblmdb.so を動的ロードするため、ランタイムライブラリをインストールする
RUN apt-get update && apt-get install -y --no-install-recommends liblmdb0 \
    && rm -rf /var/lib/apt/lists/*

# 依存ライブラリをインストールし、リレーサーバーをリリースビルドする
RUN nimble install -y
RUN rm -f nimble.paths && nim c -d:release --opt:speed -o:bin/server src/server.nim

EXPOSE 8000

CMD ["./bin/server"]
