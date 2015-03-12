#ifndef _APPBUNDLE_H_
#define _APPBUNDLE_H_

#include <string>

bool isAppBundle(const std::string &path);

class AppBundle
{
    std::string path;
    std::string name;
    std::string identifier;

    std::string _fpath, _fbinary;

    // Right now, _appname = _basename without ".app". Eventually, this might
    // want to check the InfoPlist for the binary name?
    std::string _basename, _appname;
    bool _valid;

private:
    void findPaths(const std::string &p);
    void hashInfoPlist();
    void hashCodeResources();

public:
    char specialHashes[6][20];

public:
    void loadInfoPlist();
    bool generateCodeSignatureDirectory();

public:
    AppBundle(const std::string &p);
    bool isValid() { return _valid; }

    const std::string &fullPath()           { return _fpath; }
    const std::string &fullBinaryPath()     { return _fbinary; }
    const std::string &bundleIdentifier()   { return identifier; }
};

#endif//_APPBUNDLE_H_
