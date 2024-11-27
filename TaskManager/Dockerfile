FROM maven:3.9.5-eclipse-temurin-17 AS build
WORKDIR /home/application

COPY src /home/application/src
COPY pom.xml /home/application/

RUN mvn -DskipTests=true clean package

FROM eclipse-temurin:17-jre-alpine
WORKDIR /usr/local/lib

RUN mkdir -p /usr/local/lib/logs

COPY --from=build /home/application/target/application.jar /usr/local/lib/application.jar

EXPOSE 80

ENTRYPOINT ["java", "-jar", "/usr/local/lib/application.jar"]