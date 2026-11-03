FROM python:3.12-slim
ENV DOTNET_ROOT=/usr/share/dotnet \
    PATH=$PATH:/usr/share/dotnet:/root/.dotnet/tools \
    DOTNET_ROLL_FORWARD=Major \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    ILSPY_CMD=/root/.dotnet/tools/ilspycmd \
    IL2CPP_DIR=/opt/il2cppdumper \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*
# .NET 8 SDK (ilspycmd) — Il2CppDumper net6 build runs on it via DOTNET_ROLL_FORWARD=Major
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/di.sh \
    && bash /tmp/di.sh --channel 8.0 --install-dir /usr/share/dotnet && rm /tmp/di.sh \
    && dotnet tool install -g ilspycmd
RUN mkdir -p /opt/il2cppdumper \
    && curl -fsSL -o /tmp/i.zip https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-v6.7.46.zip \
    && unzip /tmp/i.zip -d /opt/il2cppdumper && rm /tmp/i.zip
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "bot.py"]
