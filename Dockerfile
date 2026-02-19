FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /app

COPY gradlew gradlew.bat settings.gradle.kts build.gradle.kts /app/
COPY gradle /app/gradle
COPY src /app/src

RUN ./gradlew --no-daemon clean bootJar -x test

FROM eclipse-temurin:21-jre-jammy AS runtime
WORKDIR /app

COPY --from=build /app/build/libs/*.jar /app/app.jar

EXPOSE 8080
ENV JAVA_OPTS=""
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
