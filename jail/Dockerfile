# Cross-platform alternative to iptables: run the agent in a container whose only
# reachable destination is the KEYRING proxy on the host.
#   docker build -t agent-jail -f jail/Dockerfile .
#   docker run --rm -e HTTPS_PROXY=http://host.docker.internal:8080 \
#                   -e HTTP_PROXY=http://host.docker.internal:8080 agent-jail
# Lock egress with a user-defined network + firewall so ONLY the proxy is reachable.
FROM node:22-slim
RUN useradd -m agent
USER agent
WORKDIR /home/agent
CMD ["bash"]
