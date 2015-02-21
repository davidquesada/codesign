#include "identity.h"
#include "minimal/stdlib.h"
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <wordexp.h>
using namespace std;

class Identity_impl
{
    string _identityPath;
    string _identity;
public:
    Identity_impl(const string &name);
    bool isValid();
    vector<uint8_t> signMessage(const char *msg, int len);
};


Identity::Identity(const string &name) : impl(0)
{
    Identity_impl *imp = new Identity_impl(name);
    if (imp->isValid())
        this->impl = imp;
    else
        delete imp;
}

bool Identity::found()
{
    return !!impl;
}

vector<uint8_t> Identity::signMessage(const char *msg, int len)
{
    return ((Identity_impl *)this->impl)->signMessage(msg, len);
}

// Mediocre pseudo-keychain system.

Identity_impl::Identity_impl(const string &name) : _identity(name)
{
    if (!name.size())
        return;
    string path = "~/.codesign2/identities/" + _identity;
    char buf[4096];

    wordexp_t exp;
    wordexp(path.c_str(), &exp, WRDE_NOCMD);
    if (!exp.we_wordc) {
        wordfree(&exp);
        return;
    }
    path = exp.we_wordv[0];
    wordfree(&exp);

    _identityPath = realpath(path.c_str(), buf);
}

bool Identity_impl::isValid()
{
    if (!_identity.size() || !_identityPath.size())
        return false;

    struct stat st;
    if (stat(_identityPath.c_str(), &st))
        return false;
    if (!(st.st_mode & S_IFDIR))
        return false;
    return true;
}

vector<uint8_t> Identity_impl::signMessage(const char *msg, int len)
{
    vector<uint8_t> data;
    string keypath, certpath;
    string inname, outname;
    FILE *inf, *outf;
    char buf[4096];
    size_t read;

    // Determine file names.
    keypath = _identityPath + "/privateKey.pem";
    certpath = _identityPath + "/publicCert.pem";
    inname = tmpnam(buf);
    outname = tmpnam(buf);

    // Resolve the paths
    realpath(keypath.c_str(), buf);
    keypath = buf;
    realpath(certpath.c_str(), buf);
    certpath = buf;


    fprintf(stderr, "Signing infile: %s\n", inname.c_str());
    fprintf(stderr, "Signing outfile: %s\n", outname.c_str());
    
    // Write the data to a temp file.
    inf = fopen(inname.c_str(), "w");
    fwrite(msg, 1, len, inf);
    fclose(inf);

    // Fork and openssl to generate the signature.
    pid_t pid = fork();
    _syscall(pid);
    if (pid == 0) {
        std::vector<const char *> args;

        args.push_back("openssl");

        args.push_back("cms");
        args.push_back("-sign");
        args.push_back("-binary");
        args.push_back("-outform");
        args.push_back("DER");
        args.push_back("-md");
        args.push_back("SHA1");
        args.push_back("-signer");
        args.push_back(certpath.c_str());
        args.push_back("-inkey");
        args.push_back(keypath.c_str());
        args.push_back("-in");
        args.push_back(inname.c_str());
        args.push_back("-out");
        args.push_back(outname.c_str());

        string passpath = _identityPath + "/password";
        struct stat tmp;
        if (!stat(passpath.c_str(), &tmp))
        {
            args.push_back("-passin");
            passpath = "file:" + passpath;
            args.push_back(passpath.c_str());
        }

        // The real codesign also adds the Apple Root CA and Apple
        // Worldwide Developer Relations certificates.
        //args.push_back("-certfile");
        //args.push_back("AppleRootAndWWDRCerts.pem");

        args.push_back(NULL);

        if (true) {
            printf("run:");
            _foreach (arg, args)
                printf(" %s", arg);
            printf("\n");
        }

        execvp("openssl", (char **) &args[0]);
        _assert(false);
    }

    int status;
    _syscall(waitpid(pid, &status, 0));
    _assert(WIFEXITED(status));
    _assert(WEXITSTATUS(status) == 0);

    outf = fopen(outname.c_str(), "r");
    while ((read = fread(buf, 1, sizeof(buf), outf)))
        data.insert(data.end(), (uint8_t*)buf, (uint8_t*)&buf[read]);
    _assert(!ferror(outf));
    fclose(outf);

    remove(inname.c_str());
    remove(outname.c_str());

    return data;
}
