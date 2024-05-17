builder := go
builddir := bin
exe := cycarrierhw
path := /usr/local/bin
importdir := models router utils api
instdir := /usr/local/share/$(exe)
instrelativedir := $(subst /usr/local,..,$(instdir))
systemddir := /etc/systemd/system
config := .env
systemd := $(exe).service
ldflags := -s -w
tags := release

all: $(builddir)/$(exe) $(builddir)/$(config)

$(builddir)/$(exe): main.go go.mod go.sum $(importdir)
		$(builder) generate ./...
		CGO_ENABLED=0 $(builder) build -o $(builddir)/$(exe) -tags $(tags) -ldflags "$(ldflags)" $<

run: main.go go.mod go.sum $(importdir)
		$(builder) generate ./...
		$(builder) run $<

install: $(path)/$(exe) $(systemddir)/$(systemd)

$(path)/$(exe): $(instdir)/$(exe) $(instdir)/$(config)
		ln -s $(instrelativedir)/$(exe) $(path)/$(exe)

$(builddir)/$(config): $(builddir) $(config).sample
		cp $(config).sample $(builddir)/$(config)

$(instdir): 
		mkdir $(instdir)

$(instdir)/$(exe): $(instdir) $(builddir)/$(exe)
		cp $(builddir)/$(exe) $(instdir)/$(exe)
		chown root:root $(instdir)/$(exe)
		chmod 4755 $(instdir)/$(exe)

$(instdir)/$(config): $(instdir) $(config).sample
		cp $(config).sample $(instdir)/$(config)

$(systemddir)/$(systemd): $(systemd)
		cp $(systemd) $(systemddir)/$(systemd)

uninstall:
		rm -rf $(path)/$(exe)
		rm -rf $(instdir)
		rm -rf $(systemddir)/$(systemd)
clean: 
		rm -rf $(builddir)
