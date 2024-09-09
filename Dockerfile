ARG CI_REGISTRY

FROM eclipse-temurin:22.0.2_9-jdk-alpine as builder

WORKDIR /tmp

ARG JAR_FILE=target/*.jar

COPY ${JAR_FILE} application.jar
RUN ls -alF && \
    java -Djarmode=layertools -jar application.jar extract

FROM eclipse-temurin:22.0.2_9-jdk-alpine

WORKDIR /app

COPY --from=builder /tmp/dependencies/ ./
COPY --from=builder /tmp/spring-boot-loader/ ./
COPY --from=builder /tmp/snapshot-dependencies/ ./
COPY --from=builder /tmp/application/ ./

USER 1001

EXPOSE 8080

ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD curl -f -s localhost:9090/health | grep UP || exit 1
