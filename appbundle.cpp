#include "minimal/stdlib.h"
#include "minimal/mapping.h"
#include "appbundle.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <plist/plist.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <cstring>
extern "C" {
#include "sha1.h"
}

using namespace std;

static bool generateCodeResourcesFile(const string &binaryName, const string &bundleDirectory, const string &destinationFile);

bool isAppBundle(const std::string &p)
{
    string path = p;
    while (path[path.size() - 1] == '/')
        path = path.substr(0, path.size() - 1);

    struct stat st;
    if (stat(path.c_str(), &st))
        return false;
    if (!(st.st_mode & S_IFDIR))
        return false;
    if (path.size() < 5)
        return false;
    if (path.substr(path.size() - 4, 4) != ".app")
        return false;
    return true;
}

void AppBundle::loadInfoPlist()
{
    string path = _fpath + "/Info.plist";
    char buf[4096];
    FILE *file;
    vector<char> data;
    size_t read;
    plist_t root = 0;
    char *ptr = 0;

    file = fopen(path.c_str(), "r");
    while ((read = fread(buf, 1, sizeof(buf), file)))
        data.insert(data.end(), buf, &buf[read]);
    _assert(!ferror(file));
    fclose(file);

    if (!data.size())
        return;

    if (data.size() > 6 && !memcmp(&data[0], "bplist", 6))
        plist_from_bin(data.data(), data.size(), &root);
    else
        plist_from_xml(data.data(), data.size(), &root);

    plist_t bundleIdentifierNode = plist_dict_get_item(root, "CFBundleIdentifier");
    plist_get_string_val(bundleIdentifierNode, &ptr);
    this->identifier = ptr;
    free(ptr);
    ptr = NULL;

    plist_t bundleExecutableNode = plist_dict_get_item(root, "CFBundleExecutable");
    plist_get_string_val(bundleExecutableNode, &ptr);
    this->_fbinary = _fpath + "/" + ptr;
    free(ptr);
    ptr = NULL;

    plist_free(root);
}

bool AppBundle::generateCodeSignatureDirectory()
{
    string fullpath = _fpath;
    string basename = _basename;

    string signatureDirectory = fullpath + "/_CodeSignature";
    string codeResourcesFile = signatureDirectory + "/CodeResources";
    string appname = basename.substr(0, basename.size() - 4);

    string rmcmd = "rm -rf " + signatureDirectory;
    if (system(rmcmd.c_str()))
        return false;

    mkdir(signatureDirectory.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    if (!generateCodeResourcesFile(appname, fullpath, codeResourcesFile))
        return false;

    // Move these to a place that makes more sense?
    hashInfoPlist();
    hashCodeResources();

    return true;
}

// TODO: Figure out what other files are never optional.
static bool fileIsOptional(const string &relpath)
{
    const char *str = relpath.c_str();
    if (!strcmp(str, "Info.plist"))
        return false;
    if (!strcmp(str, "embedded.mobileprovision"))
        return false;
    if (!strcmp(str, "PkgInfo"))
        return false;
    if (relpath.size() >= 23)
    {
        // Plists in the settings bundles are required.
        if (!strncmp(str, "Settings.bundle/", 16) && (relpath.substr(relpath.size() - 6, 6) == ".plist"))
            return false;
    }
    return true;
}

static void loadFileHash(const string &fullpath, const string &relpath, plist_t files)
{
    size_t filesize = _not(size_t);
    const uint8_t *memregion = NULL;
    uint8_t hash[SHA1HashSize];
    SHA1Context hash_ctx;
    int result;
    plist_t hashValue;
    bool optional;
    
    memregion = (uint8_t*)map(fullpath.c_str(), 0, _not(size_t), &filesize, true);

    SHA1Reset(&hash_ctx);
    SHA1Input(&hash_ctx, memregion, (unsigned int)filesize);
    result = SHA1Result(&hash_ctx, hash);
    _assert(!result);

    optional = fileIsOptional(relpath);
    hashValue = plist_new_data((const char *)hash, SHA1HashSize);

    if (!optional)
        plist_dict_insert_item(files, relpath.c_str(), hashValue);
    else
    {
        plist_t hash_dict = plist_new_dict();
        plist_dict_insert_item(hash_dict, "hash", hashValue);
        plist_dict_insert_item(hash_dict, "optional", plist_new_bool(true));
        plist_dict_insert_item(files, relpath.c_str(), hash_dict);
    }
}

void addResourceFilesInDirectory(const string &bundleDirectory, const string &subdir,
                                 plist_t files)
{
    DIR *dir;
    dirent *entry;
    string dirpath = bundleDirectory + "/" + subdir;

    dir = opendir(dirpath.c_str());
    _assert(dir);

    while ((entry = readdir(dir))) {
        if (*entry->d_name == '.')
            continue;

        // Ignore the code signing directory. We'll also want to get rid of the binary.
        if (!subdir.size() && !strcmp(entry->d_name, "_CodeSignature"))
            continue;

        string relpath = subdir + "/" + entry->d_name;
        string fullpath = bundleDirectory + "/" + relpath;

        if (!subdir.size())
            relpath = entry->d_name;

        cout << "Found: " << relpath << endl;

        struct stat st;
        if (stat(fullpath.c_str(), &st))
            continue;
        if (st.st_mode & S_IFDIR)
        {
            addResourceFilesInDirectory(bundleDirectory, relpath, files);
            continue;
        }
        else
        {
            loadFileHash(fullpath, relpath, files);
        }
    }
    closedir(dir);
}

static void addCodeResourceRules(plist_t file)
{
    plist_t rules, dict;
    
    rules = plist_new_dict();
    plist_dict_insert_item(file, "rules", rules);
    
        plist_dict_insert_item(rules, "^", plist_new_bool(true));

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "optional", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(1000.0));
        plist_dict_insert_item(rules, "^.*\\.lproj/", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "omit", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(1100.0));
        plist_dict_insert_item(rules, "^.*\\.lproj/locversion.plist$", dict);

        plist_dict_insert_item(rules, "^version.plist$", plist_new_bool(true));


    rules = plist_new_dict();
    plist_dict_insert_item(file, "rules2", rules);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "weight", plist_new_real(11.0));
        plist_dict_insert_item(rules, ".*\\.dSYM($|/)", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "weight", plist_new_real(11.0));
        plist_dict_insert_item(rules, "^", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "omit", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(2000.0));
        plist_dict_insert_item(rules, "^(.*/)?\\.DS_Store$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "nested", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(10.0));
        plist_dict_insert_item(rules, "^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/", dict);

        plist_dict_insert_item(rules, "^.*", plist_new_bool(true));

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "optional", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(1000.0));
        plist_dict_insert_item(rules, "^.*\\.lproj/", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "omit", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(1100.0));
        plist_dict_insert_item(rules, "^.*\\.lproj/locversion.plist$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "omit", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(20.0));
        plist_dict_insert_item(rules, "^Info\\.plist$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "omit", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(20.0));
        plist_dict_insert_item(rules, "^PkgInfo$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "nested", plist_new_bool(true));
        plist_dict_insert_item(dict, "weight", plist_new_real(10.0));
        plist_dict_insert_item(rules, "^[^/]+$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "weight", plist_new_real(20.0));
        plist_dict_insert_item(rules, "^embedded\\.provisionprofile$", dict);

        dict = plist_new_dict();
        plist_dict_insert_item(dict, "weight", plist_new_real(20.0));
        plist_dict_insert_item(rules, "^version\\.plist$", dict);
}

static bool generateCodeResourcesFile(const string &binaryName, const string &bundleDirectory, const string &destinationFile)
{
    plist_t toplevel, files, files2;
    toplevel = plist_new_dict();
    _assert(toplevel);

    files = plist_new_dict();

    plist_dict_insert_item(toplevel, "files", files);
    
    addResourceFilesInDirectory(bundleDirectory, "", files);


    plist_dict_remove_item(files, binaryName.c_str());

    files2 = plist_copy(files);
    plist_dict_insert_item(toplevel, "files2", files2);

    addCodeResourceRules(toplevel);

    char *xmldata = NULL;
    uint32_t xmllen = 0;

    plist_to_xml(toplevel, &xmldata, &xmllen);
    ofstream outfile(destinationFile.c_str());
    outfile.write(xmldata, xmllen);

    free(xmldata);
    plist_free(toplevel);

    return true;
}

AppBundle::AppBundle(const string &p)
{
    memset(specialHashes, 0, sizeof(specialHashes));

    _valid = isAppBundle(p);
    if (!_valid)
        return;
    findPaths(p);
    loadInfoPlist();
}

void AppBundle::findPaths(const string &path)
{
    string fullpath, basename;
    {
        char buf[4096] = {0};
        realpath(path.c_str(), buf);
        fullpath = buf;
        char buf2[4096];
        strcpy(buf2, ::basename(buf));
       
        basename = buf2;
    }

    _fpath = fullpath;
    _basename = basename;
    _appname = basename.substr(0, basename.size() - 4);
    _fbinary = "";
}

static void hashFile(const char *filename, char *hash)
{
    size_t filesize = _not(size_t);
    const uint8_t *memregion = NULL;
    SHA1Context hash_ctx;
    int result;
    
    memregion = (uint8_t*)map(filename, 0, _not(size_t), &filesize, true);

    SHA1Reset(&hash_ctx);
    SHA1Input(&hash_ctx, memregion, (unsigned int)filesize);
    result = SHA1Result(&hash_ctx, (uint8_t*)hash);
    _assert(!result);
}

void AppBundle::hashInfoPlist()
{
    string plistpath = _fpath + "/Info.plist";
    hashFile(plistpath.c_str(), specialHashes[1]); // cdInfoSlot
}
void AppBundle::hashCodeResources()
{
    string resources = _fpath + "/_CodeSignature/CodeResources";
    hashFile(resources.c_str(), specialHashes[3]); // cdResourceDirSlot    
}
