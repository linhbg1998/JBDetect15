#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
extern char**environ;

//Don't try to patch/hook me, it's a Kids's trick!

void detect_rootlessJB()
{
    if(access("/var/jb", F_OK)==0) {
        NSLog(@"rootless JB found!");
    }
    
    if(access("/private/preboot/jb", F_OK)==0) {
        NSLog(@"Fugu15 JB found!");
    }

    char* xinafiles[] = {
        "/var/containers/Bundle/dylib",
        "/var/containers/Bundle/xina",
        "/var/mobile/Library/Preferences/com.xina.blacklist.plist",
    };
    
    for(int i=0; i<sizeof(xinafiles)/sizeof(xinafiles[0]); i++) {
        if(access(xinafiles[i], F_OK)==0) {
            NSLog(@"xina jb file found: %s", xinafiles[i]);
        }
    }
    
    char* varfiles[] = {
        "apt","bin","bzip2","cache","dpkg","etc","gzip","lib","Lib","libexec","Library","LIY","Liy","newuser","profile","sbin","sh","share","ssh","sudo_logsrvd.conf","suid_profile","sy","usr","zlogin","zlogout","zprofile","zshenv","zshrc", "master.passwd"
    };
    for(int i=0; i<sizeof(varfiles)/sizeof(varfiles[0]); i++) {
        NSString* path=[NSString stringWithFormat:@"/var/%s", varfiles[i]];
        if(access(path.UTF8String, F_OK)==0) {
            NSLog(@"xina jb file found: %@", path);
        }
    }
}

void detect_kernBypass()
{
    if(access("/private/var/MobileSoftwareUpdate/mnt1/System", F_OK)==0)
    {
        NSLog(@"kernBypass installed!");
    }
}

void detect_chroot()
{
    struct statfs s={0};
    statfs("/", &s);
    if(strcmp("/", s.f_mntonname)!=0) {
        NSLog(@"chroot found! %s", s.f_mntonname);
    }
}

void detect_mount_fs()
{
    struct statfs * ss=NULL;
    int n = getmntinfo(&ss, 0);
    for(int i=0; i<n; i++) {
        //printf("mount %s %s : %s : %x,%x\n", ss[i].f_fstypename, ss[i].f_mntonname, ss[i].f_mntfromname, ss[i].f_flags, ss[i].f_flags_ext);
        
        if(strcmp("/", ss[i].f_mntonname)!=0 && strstr(ss[i].f_mntfromname, "@")!=NULL) {
            NSLog(@"unexcept snap mount! %s => %s", ss[i].f_mntfromname, ss[i].f_mntonname);
        }
        
        for(int j=0; j<i; j++) {
            if(strcmp(ss[i].f_mntfromname, ss[j].f_mntfromname)==0) {
                NSLog(@"double mount: %s", ss[i].f_mntfromname);
            }
        }
    }
}

void detect_bootstraps()
{
    if(access("/var/log/apt", F_OK)==0) {
        NSLog(@"apt log found!");
    }
    
    if(access("/var/log/dpkg", F_OK)==0) {
        NSLog(@"dpkg log found!");
    }
    
    if(access("/var/lib/dpkg", F_OK)==0) {
        NSLog(@"dpkg found!");
    }
    
    if(access("/var/lib", F_OK)==0) {
        NSLog(@"var lib found!");
    }
    
    if(access("/var/lib/apt", F_OK)==0) {
        NSLog(@"apt found!");
    }
    
    if(access("/var/lib/cydia", F_OK)==0) {
        NSLog(@"cydia found!");
    }
    
    if(access("/var/lib/undecimus", F_OK)==0) {
        NSLog(@"unc0ver found!");
    }
    
    if(access("/var/mobile/Library/Sileo", F_OK)==0) {
        NSLog(@"Sileo found!");
    }
    
    if(access("/var/mobile/Library/Application Support/xyz.willy.Zebra", F_OK)==0) {
        NSLog(@"Zebra found!");
    }
}

void detect_trollStoredFilza()
{
    if(access("/var/lib/filza", F_OK)==0) {
        NSLog(@"trollStoredFilza found!");
    }
    
    if(access("/var/mobile/Library/Filza", F_OK)==0) {
        NSLog(@"trollStoredFilza found!");
    }
    
    if(access("/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist", F_OK)==0) {
        NSLog(@"trollStoredFilza found!");
    }
}

kern_return_t bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

static mach_port_t connect_mach_service(const char *name) {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = bootstrap_look_up(bootstrap_port, (char *)name, &port);
  return port;
}

void detect_jailbreakd()
{
    if(connect_mach_service("cy:com.saurik.substrated")) {
        NSLog(@"checkra1n substrated found!");
    }
    
    if(connect_mach_service("org.coolstar.jailbreakd")) {
        NSLog(@"coolstar jailbreakd found!");
    }
    
    if(connect_mach_service("jailbreakd")) {
        NSLog(@"xina jailbreakd found!");
    }
}

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
void detect_proc_flags()
{
    uint32_t flags = 0;
    csops(getpid(), 0, &flags, 0);
    //NSLog(@"csops=%08X", flags); //22003305/lldb32003004=>3600700D, 22003305/lldb32003005
    
    if(flags & 0x00000004) {
        NSLog(@"get-task-allow found!");
    }
    if(flags & 0x04000000) {
        NSLog(@"unexcept platform binary!");
    }
    if(flags & 0x00000008) {
        NSLog(@"unexcept installer!");
    }
    if(!(flags & 0x00000300)) {
        NSLog(@"jit-allow found!");
    }
    if(flags & 0x00004000) {
        NSLog(@"unexcept entitlements!");
    }
}

void detect_jb_payload()
{
    mach_port_t object_name;
    mach_vm_size_t region_size=0;
    mach_vm_address_t region_base = (uint64_t)vm_region_64;

    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;

    vm_region_64(mach_task_self(), (vm_address_t*)&region_base, (vm_size_t*)&region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
    
    if(info.protection != VM_PROT_READ) {
        NSLog(@"jb payload injected!");
    }
}

void detect_exception_port()
{
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count=0;
    
    mach_port_t task = mach_task_self();

    task_get_exception_ports(task, EXC_MASK_ALL, masks, &count, ports, behaviors, flavors);

    //NSLog(@"got exception ports count=%d\n", count);

    for (int i = 0;i < count; i++)
    {
        //NSLog(@"port[%d] mask=%08X port=%08X behavior=%08X flavor=%08X\n", i, masks[i], ports[i], behaviors[i], flavors[i]);
        //default: port[0] mask=00001BFE port=00000000 behavior=00000000 flavor=00000000
        //some jailbreak will set launchd exception port and subproces will auto inherit it.
        //to restore it we can task_set_exception_ports(task, 0x00001BFE, MACH_PORT_NULL, 0, 0));
        if((masks[i] & EXC_MASK_BAD_ACCESS) && ports[i]) {
            NSLog(@"unexept exception port %08X", ports[i]);
        }
    }
}

void detect_jb_preboot()
{

    {
        struct statfs s={0};
        statfs("/usr/standalone/firmware", &s);
        NSString* path = [NSString stringWithFormat:@"%s/../../../procursus", s.f_mntfromname];
        if(access(path.UTF8String, F_OK)==0) {
            NSLog(@"jb files in preboot!");
        }
    }
    
    {
        struct statfs s={0};
        statfs("/private/preboot", &s);
        if(!(s.f_flags & MNT_RDONLY)) {
            NSLog(@"preboot writeable!");
        }
    }
}

void detect_jailbroken_apps()
{
    char* appids[] = {
        "com.xina.jailbreak",
        "com.opa334.Dopamine",
        "com.tigisoftware.Filza",
        "org.coolstar.SileoStore",
        "ws.hbang.Terminal",
        "xyz.willy.Zebra",
        
    };
    
    char* paths[][3] = {
        {"","Library/Preferences",".plist"},
        {"","Library/Application Support/Containers",""},
        {"","Library/SplashBoard/Snapshots",""},
        {"","Library/Caches",""},
        {"","Library/Saved Application State",".savedState"},
        {"","Library/WebKit",""},
        {"","Library/Cookies",".binarycookies"},
        {"","Library/HTTPStorages",""},
    };
    
    for(int i=0; i<sizeof(paths)/sizeof(paths[0]); i++) {
        for(int j=0; j<sizeof(appids)/sizeof(appids[0]); j++) {
            NSString* mobile = [NSString stringWithFormat:@"/var/mobile/%s/%s%s%s", paths[i][1], appids[j], paths[i][0], paths[i][2]];
            if(access(mobile.fileSystemRepresentation, F_OK)==0) {
                printf("jailbroken app found %s\n", mobile.UTF8String);
            }
            NSString* root = [NSString stringWithFormat:@"/var/root/%s/%s%s%s", paths[i][1], appids[j], paths[i][0], paths[i][2]];
            if(access(root.fileSystemRepresentation, F_OK)==0) {
                printf("jailbroken app found %s\n", root.UTF8String);
            }
        }
    }
}

void detect_removed_varjb()
{
    /*
     Maybe you temporarily delete this symlink, but you can't guarantee that you will never make a mistake.
     
     And you never know which app will add this detection in the next update,
        unless you remove this symbolic link before opening every app, but then you will go crazy.
     */
    char* buf[PATH_MAX]={0};
    if(readlink("/var/jb", buf, sizeof(buf))>0) {
        //we can save the link to userDefaults/keyChains/pasteBoard, or send to server and bind it to your device-id/app-account
        [NSUserDefaults.standardUserDefaults setObject:[NSString stringWithUTF8String:buf] forKey:@"/var/jb"];
    }
    
    NSString* saved = [NSUserDefaults.standardUserDefaults stringForKey:@"/var/jb"];
    if(access(saved.UTF8String, F_OK)==0) {
        NSLog(@"removed /var/jb found! %s", saved.UTF8String);
    }
}

void detect_fugu15Max()
{
    if(access("/usr/lib/systemhook.dylib", F_OK)==0) {
        NSLog(@"systemhook.dylib found!");
    }
    if(access("/usr/lib/sandbox.plist", F_OK)==0) {
        NSLog(@"sandbox.plist found!");
    }
    if(access("/var/log/launchdhook.log", F_OK)==0) {
        NSLog(@"launchdhook.log found!");
    }
    
    struct statfs s={0};
    statfs("/usr/lib", &s);
    if(strcmp("/", s.f_mntonname)!=0) {
        NSLog(@"fakelib found! %s", s.f_mntfromname);
    }
}

void detect_url_schemes()
{
    //jailbroken app's scheme doesn't need to define in Info.plist ?
    char* schemes[] = {
        "sileo",
        "zbra",
        "cydia",
        "installer",
        "apt-repo",
        "filza",
    };
    
    for(int i=0; i<sizeof(schemes)/sizeof(schemes[0]); i++) {
        BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:[NSString stringWithFormat:@"%s://",schemes[i]]]];
        if(canOpen) NSLog(@"URLScheme found: %s", schemes[i]);
    }
}

#import "AppDelegate.h"
int main(int argc, char * argv[])
{
    NSLog(@"Don't try to patch/hook me, it's a Kids's trick!");

    detect_rootlessJB();
    detect_kernBypass();
    detect_chroot();
    detect_mount_fs();
    detect_bootstraps();
    detect_trollStoredFilza();
    detect_jailbreakd();
    detect_proc_flags();
    detect_exception_port();
    detect_jb_payload();
    detect_jb_preboot();
    detect_jailbroken_apps();
    detect_removed_varjb();
    detect_fugu15Max();
    dispatch_async(dispatch_get_main_queue(), ^{
        detect_url_schemes();
    });

    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
