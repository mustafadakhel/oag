FROM eclipse-temurin:21-jdk-alpine AS jre-build

COPY oag-app/build/libs/*-all.jar /app/oag.jar

RUN jdeps --ignore-missing-deps --multi-release 21 \
    --print-module-deps /app/oag.jar > /modules.txt && \
    jlink --compress=zip-6 --strip-debug --no-header-files --no-man-pages \
    --add-modules $(cat /modules.txt) \
    --output /custom-jre

FROM alpine:3.21

RUN addgroup -S oag && adduser -S oag -G oag

COPY --from=jre-build /custom-jre /opt/java
COPY --from=jre-build /app/oag.jar /app/oag.jar

USER oag
WORKDIR /config

EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["/opt/java/bin/java", "-jar", "/app/oag.jar"]
CMD ["run", "--policy", "/config/policy.yaml", "--log", "/logs/audit.jsonl"]
