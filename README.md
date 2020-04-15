# IT-C-566-Forensics-Toolkit


## Tool:osxpmem.app

### Description 
oxspmem is a forensics program that can be used to perform memory captures on Mac computers. It is lightweight, and can be put on a portable hard drive (ideally in a separate partition from the location where the capture will be stored).

### Review 
With a lot of subtle differences between old and current versions of osxpmem, many tutorials for this tool are outdated and just different enough to make you pull out your hair. However, with a little determination and persistence, you should be able to get by with it.

### Notes
How to use:
☐ Attach storage device containing most current osxmem release 
☐ Open folder containing osxmem 
☐ Sudo su for privileges 
☐If necessary, unzip package. 
☐ Change directory into the osxpmem.app folder: cd osxpmem.app/ 
☐ Run osxmem. $ ./osxpmem.app/osxpmem -o <output_dir_on_storage_device>  (see error handling if blocked on this step) 
☐ Remove the storage device after files copy successfully \ 
 
Handling errors:
 Try using the native utility kextutil’s test parameter to detect any issues: 
sudo kextutil -t osxpmem.app/MacPmem.kext/ 
If the error is file permissions, use the following command to obtain permission. 
sudo chown -R root:wheel osxpmem.app/

Source URL: http://www.rekall-forensic.com/ or https://github.com/google/rekall/releases


## Tool: Wireshark

### Description
Wireshark is a GUI-interface for packet-capturing. It is extremely flexible and powerful, but its interfaces are simple enough that even a novice can quickly orient themselves.

### Review
Wireshark is the standard with good reason. Its biggest shortcomings are reflections of its intended audience, rather than shortcomings of its design: it is more resource-intensive than tcpdump or a similar CLI program, but of course, this interface makes it much more user-friendly. The other issue that I run into is that it is easy to drown in data when you examine a capture, but this is symptomatic of networks themselves, not the tool. Additionally, Wireshark has extensive filtering options to help manage outputs. 

### Notes
Wireshark is extensively documented, and I've never had to take very specific notes on use since the information was painless to Google. If you do find yourself stuck, however, https://www.wireshark.org/docs/wsug_html/ is a excellent resource for finding specific examples and step-by-step tutorials.

### Source URL
https://www.wireshark.org/download.html

## Tool: FTK Imager

### Description
FTK Imager is a tool which can be used to capture images of compromised or seized computers to be preserved as evidence during an investigation. It offers many different options for how the image is captured or stored, including bit-level copies. 

### Review
FTK Imager is straightforward to use, provided you are able to navigate the registration/licensing process. It isn't particularly flashy, but it is capable. Additionally, it is the only product of its kind available through a company based in the US, which might be significant to some crime investigation departments.

### Notes
FTK is well-documented on the internet. Here is a tutorial to get you started: https://www.hackingarticles.in/step-by-step-tutorial-of-ftk-imager-beginners-guide/

### Source URL
https://marketing.accessdata.com/ftkimager4.2.0


## Tool:netcat

### Description
Netcat is an extremely flexible networking tool, deserving of far more attention than I can give it here. One application for forensics is that it can be used to set a listener on a remote system, and send information over the network to a forensics computer. It can be run on both Linux and Windows systems.  

### Review
Netcat can be really intimidating as a newcomer, as it is an extremely deep tool. However, if you ease into it, experimenting with some of its less advanced commands, you quickly appreciate its utility. 

### Notes
Using netcat to connect a remote compter to a forensics device: 
Target host:
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc -l 127.0.0.1 1234 > /tmp/f

Forensics host:
nc (host ip) 1234

Using netcat to copy a remote computer to a forensics device:
1. Forensics host: nc -L -p 1234 > file.ext
2. Target host: sudo dd if=/dev/sda1 | netcat 192.168.100.46 1234

### Source URL
Linux: https://sourceforge.net/projects/nc110/ (but I would recommend using your favorite package manager)
Windows: https://eternallybored.org/misc/netcat/


## Tool:dd

### Description
dd is a utility for copying files frequently installed by default on Linux systems. The syntax for dd is of the general form dd if=<path> of=<path>. “If” specifies the subject to be copied, and “of” specifies the destination. Instead of specifying a destination, however, dd can be piped into another application instead, such as with netcat. 
  
### Review
dd is relatively simple to use, and a staple of working with Linux systems. Virtually all technologists should have some familiarity with it.

### Notes
Good resource for dd: https://www.geeksforgeeks.org/dd-command-linux/

### Source URL
dd is built into Unix and Unix-like operating systems by default.


## Tool:LiME

### Description
LiME is a software package designed to capture volatile memory from Linux systems. It 

### Review
LiME is tricky to set up the first time, and online resources will often miss important details during their walkthroughs. However, it is basically the only option out there for Linux memory captures, and so scarcity is its virtue. 

### Notes
Copy LiME repository with git:
git clone https://github.com/504ensicsLabs/LiME

Change directory to LiME folder, and compile the code in the folder
cd LiME/src && make

The directory should now contain a file with a name like “lime-x.x.x.xx.ko”. Use insmod to insert the kernel module, define the destination, and format for the image you create:
insmod lime-2.6.32-696.23.1.el6.x86_64.ko "path=/Linux64.mem format=lime"

To ensure that the LiME module has been loaded, run lsmod | grep -i lime. This should return something like 
lime                   12926  1

The memory dump has been stored in a file called Linux64.mem.

### Source URL
https://github.com/504ensicsLabs/LiME


## Tool:Snort

### Description
Snort is a flexible network monitoring tool that can function as an IPS/IDS. I have personally used Snort in IDS mode to scan a pcap file for malicious activity. If Snort detected something matching its configured parameters, it will log the issue for my review. 

### Review
Snort is a fairly approachable system for packet-sniffing, though there are a lot of different options for configuration depending on the application. Google is your best friend for figuring it out.

### Notes
None. 

### Source URL
https://www.snort.org/


## Tool:Caploader

### Description
Caploader is a tool that pulls and summarizes metadata from a packet capture for inspection. Some of the features I used CapLoader for are the “Hosts” and “Flows” tabs. Hosts identifies all unique IPs, and Flows identifies all conversations between unique IPs within the .pcap file. This can be helpful for tracking the flow of suspicious files across a network, and the hostnames associated with IP addresses.

### Review
Caploader's interface is friendly and intuitive. The tool is not extremely deep based on my use, but it works well within that scope. 

### Notes
None

### Source URL
https://www.netresec.com/?page=CapLoader

## Tool:Volatility

### Description
Volatility is an open-source virtual memory analysis tool compatible with most operating systems. Its functionality can be extended with scripts called plugins. Volatility is helped by an active community, which writes new scripts and extends existing ones. 

### Review
Volatility is a deep tool, with extensive customization and flexibilty. Despite that, using it isn't quite as difficult as it sounds, and it works well. 

### Notes
See the github for information on running Volatility.

### Source URL
https://github.com/volatilityfoundation/volatility

## Tool:VirusTotal

### Description
VirusTotal is an online virus-scanning tool which sends out samples of code to different anti-virus platforms to determine if the output matches any known virus signatures. Samples can be uploaded as files, from which point VirusTotal distributes them and fabricates a report. VirusTotal’s major appeal is its integration with many different anti-virus systems, which ensures a broader detection net than reliance on any one tool.

### Review
Virustotal is extremely simple to use: upload a suspicious file and wait to see if the signature-matching discovers something malicious. This is valuable for quick tests and sanity checks. 

### Notes
Just upload the file and read the output. 

### Source URL
https://www.virustotal.com/gui/home


## Tool:Autopsy

### Description
Autopsy is an open-source digital forensics platform designed to be intuitive and accessible with a limited budget. It provides the same core functionality as many commercial platforms and has an adaptive structure that allows it to interface third-party modules. 

### Review
I found Autopsy to be quite user-friendly. After loading a memory capture, it was easy to browse the file structure and find information. It also has extensive tools for documenting your process, and capturing information hidden in unallocated space (as well as other obfuscation techniques). 

### Notes
None

### Source URL
https://www.autopsy.com/


## Tool:Yara

### Description
Yara is a program that uses signature-matching to find malware. Yara allows the creation of custom rules in .yara files.

### Review
Yara is hard to get running, and the way rules are formed can be challenging to understand. Once I had it running and had experimented for a few hours, however, the learning curve grew less steep. 

### Notes
Documentation:  https://yara.readthedocs.io/

Example rules: 
rule RuleA
{
    meta:
        author = "Joseph Belyeu"
        date = "3/28/2020"
        description = "This is a basic rule looking for a combination of multiple strings"

    strings:
        $firstPattern = "super suspicious string that probably doesn't exist"
        $secondPattern = "equally suspicious string that we're looking for"

    condition:
        $firstPattern or $secondPattern
}

rule RuleB
{
    meta:
        author = "Joseph Belyeu"
        date = "3/28/2020"
        description = "This is a basic rule demonstrating the use of keywords, such as nocase"

    strings:
        $firstPattern = "WORD" nocase

        $secondPattern = "email" ascii wide

    condition:
        $firstPattern or $secondPattern
}

rule RuleC
{
    meta:
        author = "Joseph Belyeu"
        date = "3/28/2020"
        description = "This is a basic rule looking for a combination of hex strings"

    strings:
        $firstPattern = { 57 4f 52 44 } 

        $secondPattern = { 65 6d 61 69 6c } 

    condition:
        $firstPattern or $secondPattern
}

rule RuleD
{
    meta:
        author = "Joseph Belyeu"
        date = "3/28/2020"
        description = "This is a basic rule demonstrating regular expressions"

    strings:
        $re1 = /WORD|email/ nocase

    condition:
        $re1
}

rule RuleE
{
    meta:
        author = "Joseph Belyeu"
        date = "3/28/2020"
        description = "This is a basic rule demonstrating matching with uint functions"

    condition:
       uint16(0) == 0x574f5244 or uint16(0) == 0x656d61696c
}

### Source URL
https://github.com/VirusTotal/yara

## Tool:Grep

### Description
Grep is a simple tool used to find certain lines in a file or output, often used by system administrators to isolate entries in a log file, or simplify an output in a terminal (think of it as ctrl + f for terminal). It is build into Unix and Unix-like operating systems by default.

### Review
Get comfortable with grep: it will make your life in the terminal much, much easier.

### Notes
grep <string or expression> -c <filename>
  
### Source URL
http://man7.org/linux/man-pages/man1/grep.1.html (grep man page)


## Tool:Radare

### Description
Radare is a multi-faceted reverse-engineering framework. It incorporates a wide suite of simple tools, but I am most familiar with its ability to disassemble and modify assembly code.

### Review
Radare isn't very well known, so documentation can be a little spotty. Additionally, many of its interfaces are far from intuitive. Hoewver, it is extremely powerful, and certainly justifies the investment of time and energy to get to know it well.

### Notes
The most helpful resource for me as I got started was this page from the documentation: https://monosource.gitbooks.io/radare2-explorations/content/intro/editing.html

Other resources that helped me include: 
https://reverseengineering.stackexchange.com/questions/14223/edit-instructions-directly-in-visual-mode on writing assembly with the wa command

### Source URL
https://rada.re/n/
