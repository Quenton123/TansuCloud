# syntax=docker/dockerfile:1.7
# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# Runtime stage (used by VS fast mode and production)
FROM mcr.microsoft.com/dotnet/aspnet:9.0-noble-chiseled AS base
ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_EnableDiagnostics=0
USER $APP_UID
WORKDIR /app
EXPOSE 8080

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0-noble AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# restore with cache (requires BuildKit)
COPY ["TansuCloud.Gateway.csproj", "."]
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    --mount=type=cache,id=dotnetobj,target=/src/obj \
    dotnet restore "./TansuCloud.Gateway.csproj"

# copy the rest of the sources
COPY . .

# Publish directly (build is implied) using cache for packages and intermediate outputs
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    --mount=type=cache,id=dotnetobj,target=/src/obj \
    dotnet publish "./TansuCloud.Gateway.csproj" -c $BUILD_CONFIGURATION -o /app/publish \
      -p:UseAppHost=false

# Final stage
FROM base AS final
ARG BUILD_VERSION=unknown
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED
LABEL org.opencontainers.image.title="TansuCloud Gateway" \
      org.opencontainers.image.description="YARP API Gateway for Tansu.cloud (tenant routing, JWT validation, rate limiting)" \
      org.opencontainers.image.source="https://github.com/MusaGursoy/TansuCloud" \
      org.opencontainers.image.url="https://github.com/MusaGursoy/TansuCloud" \
      org.opencontainers.image.documentation="https://github.com/MusaGursoy/TansuCloud" \
      org.opencontainers.image.vendor="Tansu.cloud" \
      org.opencontainers.image.version=$BUILD_VERSION \
      org.opencontainers.image.revision=$BUILD_REVISION \
      org.opencontainers.image.created=$BUILD_CREATED \
      org.opencontainers.image.licenses="AGPL-3.0"
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "TansuCloud.Gateway.dll"]