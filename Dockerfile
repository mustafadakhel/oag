FROM eclipse-temurin:21-jre-alpine

RUN addgroup -S oag && adduser -S oag -G oag

COPY oag-app/build/libs/*-all.jar /app/oag.jar

USER oag
WORKDIR /config

EXPOSE 8080
EXPOSE 9090

ENTRYPOINT ["java", "-jar", "/app/oag.jar"]
CMD ["run", "--policy", "/config/policy.yaml", "--log", "/logs/audit.jsonl"]
