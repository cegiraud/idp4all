FROM cgr.dev/chainguard/graalvm-native

WORKDIR /app

COPY ./target/idp4all /app/idp4all

EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["./idp4all"]