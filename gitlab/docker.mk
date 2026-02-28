GITLAB_DOCKER_IMAGES := \
$(gs)docker/centos-7-amd64/Dockerfile \
$(gs)docker/centos-8-amd64/Dockerfile \
$(gs)docker/rocky-08-amd64/Dockerfile \
$(gs)docker/rocky-09-amd64/Dockerfile \
$(gs)docker/oracle-08-amd64/Dockerfile \
$(gs)docker/oracle-09-amd64/Dockerfile \
$(gs)docker/oracle-10-amd64/Dockerfile \
$(gs)docker/opensuse-15.0-amd64/Dockerfile \
$(gs)docker/opensuse-15.1-amd64/Dockerfile \
$(gs)docker/opensuse-15.2-amd64/Dockerfile \
$(gs)docker/opensuse-15.3-amd64/Dockerfile \
$(gs)docker/opensuse-15.4-amd64/Dockerfile \
$(gs)docker/opensuse-15.5-amd64/Dockerfile \
$(gs)docker/opensuse-16.0-amd64/Dockerfile \
$(gs)docker/fedora-33-amd64/Dockerfile \
$(gs)docker/fedora-34-amd64/Dockerfile \
$(gs)docker/fedora-35-amd64/Dockerfile \
$(gs)docker/fedora-36-amd64/Dockerfile \
$(gs)docker/fedora-37-amd64/Dockerfile \
$(gs)docker/fedora-38-amd64/Dockerfile \
$(gs)docker/fedora-39-amd64/Dockerfile \
$(gs)docker/fedora-40-amd64/Dockerfile \
$(gs)docker/fedora-41-amd64/Dockerfile \
$(gs)docker/fedora-42-amd64/Dockerfile \
$(gs)docker/fedora-43-amd64/Dockerfile \
$(gs)docker/fedora-44-amd64/Dockerfile \
$(gs)docker/debian-11-amd64/Dockerfile \
$(gs)docker/debian-11-i386/Dockerfile \
$(gs)docker/debian-12-amd64/Dockerfile \
$(gs)docker/debian-12-i386/Dockerfile \
$(gs)docker/debian-13-amd64/Dockerfile \
$(gs)docker/debian-13-i386/Dockerfile \
$(gs)docker/debian-testing-amd64/Dockerfile \
$(gs)docker/debian-testing-i386/Dockerfile \
$(gs)docker/ubuntu-18.04-amd64/Dockerfile \
$(gs)docker/ubuntu-20.04-amd64/Dockerfile \
$(gs)docker/ubuntu-22.04-amd64/Dockerfile \
$(gs)docker/ubuntu-24.04-amd64/Dockerfile \
$(gs)docker/ubuntu-25.04-amd64/Dockerfile \
$(gs)docker/ubuntu-25.10-amd64/Dockerfile \
$(gs)docker/ubuntu-26.04-amd64/Dockerfile \


gitlab-docker: $(GITLAB_DOCKER_IMAGES)


$(gs)docker/centos-7-amd64/Dockerfile: $(gs)docker.mk.j2 $(gs)data.yml.j2
	@echo "KEEP $@ (marked as static)"
	touch $@











































