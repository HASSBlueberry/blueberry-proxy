FROM docker.io/library/eclipse-temurin:25-jdk-jammy AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/technomancy/leiningen/stable/bin/lein \
      -o /usr/local/bin/lein \
    && chmod +x /usr/local/bin/lein

WORKDIR /build

COPY project.clj ./
RUN lein deps

COPY src ./src
COPY resources ./resources
RUN lein uberjar

FROM docker.io/library/eclipse-temurin:25-jre-jammy

LABEL org.opencontainers.image.title="blueberryProxy" \
      org.opencontainers.image.description="DNS proxy with interception, DoH, admin API and LAN scanning"

COPY --from=build /build/target/uberjar/*-standalone.jar /opt/blueberryProxy.jar

VOLUME /data

EXPOSE 53/tcp 53/udp 8053/tcp 8054/tcp 8080/tcp 8055/tcp 8056/tcp

CMD ["java", "-XX:+UseSerialGC", "-Xms96m", "-Xmx512m", "-jar", "/opt/blueberryProxy.jar"]
