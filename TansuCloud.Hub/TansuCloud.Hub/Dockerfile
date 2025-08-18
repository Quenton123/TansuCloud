# syntax=docker/dockerfile:1.7
# Optimized, production-grade Dockerfile similar to Gateway/Identity

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

# restore with cache (requires BuildKit). Compose build context is repo root.
COPY ["TansuCloud.Hub/TansuCloud.Hub/TansuCloud.Hub.csproj", "TansuCloud.Hub/TansuCloud.Hub/"]
COPY ["TansuCloud.Hub/TansuCloud.Hub.Client/TansuCloud.Hub.Client.csproj", "TansuCloud.Hub/TansuCloud.Hub.Client/"]
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    --mount=type=cache,id=hubobj,target=/src/TansuCloud.Hub/TansuCloud.Hub/obj \
    dotnet restore "./TansuCloud.Hub/TansuCloud.Hub/TansuCloud.Hub.csproj"

# copy the rest of the sources
COPY . .

# Publish directly (build is implied) using cache for packages and intermediate outputs
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    --mount=type=cache,id=hubobj,target=/src/TansuCloud.Hub/TansuCloud.Hub/obj \
    dotnet publish "./TansuCloud.Hub/TansuCloud.Hub/TansuCloud.Hub.csproj" -c $BUILD_CONFIGURATION -o /app/publish \
      -p:UseAppHost=false

# Final stage
FROM base AS final
ARG BUILD_VERSION=unknown
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED
LABEL org.opencontainers.image.title="TansuCloud Hub" \
      org.opencontainers.image.description="Blazor Web App (Hub) for Tansu.cloud (admin/tenant/user portal)" \
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
ENTRYPOINT ["dotnet", "TansuCloud.Hub.dll"]