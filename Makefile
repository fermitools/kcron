current_dir:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

_default:
	@mkdir -p build
	@echo "Perhaps you want:"
	@echo "cd ./build && cmake .. && make && make test"
sources:
	@echo "You found my koji hook"
	@mkdir kcron
	@cp -r doc src CMakeLists.txt LICENSE README.md kcron
	tar cf - kcron | gzip --best > $(current_dir)/kcron.tar.gz
	rm -rf kcron
srpm: sources
	@echo "You found my copr hook"
	rpmbuild -bs --define '_sourcedir $(current_dir)' --define '_srcrpmdir $(current_dir)/SRPMS' fermilab-util_kcron.spec
rpm: sources
	@echo "You found my 'just build it' hook"
	rpmbuild -bb --define '_rpmdir $(current_dir)/RPMS' --define '_builddir $(current_dir)' --define '_sourcedir $(current_dir)' fermilab-util_kcron.spec
