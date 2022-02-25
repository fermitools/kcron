_default:
	@mkdir -p build
	@echo "Perhaps you want:"
	@echo "cd ./build && cmake .. && make && make test"
sources:
	@echo "You found my koji hook"
	@mkdir kcron
	@cp -r doc src CMakeLists.txt LICENSE README.md kcron
	tar cf - kcron | gzip --best > kcron.tar.gz
	rm -rf kcron
srpm: sources
	@echo "You found my copr hook"
	rpmbuild -bs --define '_sourcedir .' --define '_srcrpmdir .' fermilab-util_kcron.spec
