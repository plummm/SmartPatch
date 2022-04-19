import logging
import json
import os
import argparse
import subprocess

# The earlist commit we plan to go
commit_v4_9 = "69973b830859"
commit_tale = {}

def sub_match(sub, line):
   return (sub in line) or sub == ""

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-linux', nargs='?', action='store',
                        help='the full path of linux kernel source code')
    parser.add_argument('-patch', nargs='?', action='store',
                        help='path of the patch json')                  
    args = parser.parse_args()
    return args

class Patch:
    def __init__(self, linux_path, config_path="./patch.json"):
        self.linux_path = linux_path
        self.config_path = config_path
        self.logger = self.__init_logger()
        self.version = self.__get_linux_version()

    def __init_logger(self):
        logger = logging.getLogger(__name__)
        return logger

    def __get_linux_version(self):
        cmd = ['git', 'rev-parse', 'HEAD']
        r = subprocess.run(cmd, cwd=self.linux_path, stdout=subprocess.PIPE)
        output = r.stdout.split(b'\n')
        if len(output)>0:
            return output[0].decode("utf-8").strip('\n').strip('\r')
        else:
            #self.logger.error("invalid linux version: {}".format(r.stdout))
            raise Exception("invalid linux version: {}".format(r.stdout))
        return None

    def run(self):
        patch_info = self.read_patch_info()
        if len(patch_info) > 0:
            rejected_patches = self.apply_patch(patch_info)
            if len(rejected_patches) > 0:
                for path in rejected_patches:
                    rej = rejected_patches[path]
                    self.logger.info("reject patch for {}".format(path))
                    self.parse_rejected_info(rej)
                    return 1
        return 0

    def read_patch_info(self):
        data = {}
        with open(self.config_path) as json_file:
            data = json.load(json_file)
        return data
    
    def apply_patch(self, patches):
        rejected = {}
        for path in patches:
            if os.path.exists(os.path.join(self.linux_path, path)):
                self.logger.debug("applying a patch for {}".format(path))
                for i in range(0, len(patches[path])):
                    change = patches[path][i]
                    rej, item = self.apply_change(path, change)
                    if rej:
                        if path not in rejected:
                            rejected[path] = []
                        rejected[path].append(item)
            else:
                self.logger.info("{} do not exist".format(path))
        return rejected
    
    # rejected represents if a patch has been rejected (True/False)
    # last represents the succeed or rejected change if it's not None.
    # if last is None, means no valid change found for current version
    def apply_change(self, path, change):
        last = None
        rejected = True
        for each in change:
            if self.version_out_of_range(each['from_version'], each['to_version'], self.version):
                continue
            last = each
            rejected = True
            # A single change has been cut into serval changes in some kernel versions
            if len(each['fragments']) > 0:
                apply_all_changes = True
                for e in each['fragments']:
                    rej, item = self.apply_change(path, e)
                    if rej:
                        last = item
                        apply_all_changes = False
                        break
                if apply_all_changes:
                    rejected = False
                if rejected:
                    # be rejected
                    break
                if item != None:
                    # successfully apply the changes
                    break
                # no valid patch for current version
                continue
            from_version = each['from_version']
            to_version = each['to_version']
            # Check if the to_version is inside the range from from_verison to self.version
            # Sometime two commit trees are seperate from each other. But anyway the patch haven't applied yet.
            if self.version_out_of_range(from_version, to_version, self.version):
                rejected = False
                last = None
                continue
            mother_function = each['mother_function']
            pattern_before = each['pattern_before']
            pattern_behind = each['pattern_behind']
            bottom = each['bottom']
            text = each['text']
            replace = each['replace']
            file_path = os.path.join(self.linux_path, path)
            with open(file_path, 'r+') as f:
                bracket = 1 #if no mother_function specified, pattern match can happen anywhere
                inside_func = False
                code = f.readlines()
                i = 0
                for i in range(0, len(code)):
                    if bottom:
                        i = len(code)
                        rejected = False
                        break
                    line = code[i]
                    if len(mother_function) > 0:
                        if sub_match(mother_function, line):
                            bracket = 0
                            inside_func = True
                    if inside_func:
                        if sub_match('{', line):
                            bracket += 1
                        if sub_match('}', line):
                            bracket -= 1
                    if bracket <= 0 :
                        continue
                    if self.pattern_match(pattern_before, pattern_behind, replace, code, i):
                        i += 1
                        rejected = False
                        break
                if not rejected:
                    new_code = "".join(code[:i]) + text
                    if len(replace) > 0:
                        i += 1
                    new_code += "".join(code[i:])
                    f.seek(0)
                    f.write(new_code)
                    f.truncate()
                break
        if rejected and last['ignore_rej']:
            rejected = False
        return rejected, last

    def parse_rejected_info(self, rejected):
        each = rejected[0]
        if len(each['fragments']) == 0:
            self.logger.info("failed to apply. \n\
                from_version: {}\n\
                to_version: {}\n\
                mother_function: {}\n\
                pattern_before: {}\n\
                pattern_behind: {}\n\
                replace: {}\n\
                text {}".format(each['from_version'], each['to_version'], each['mother_function'], each['pattern_before'], each['pattern_behind'], each['replace'], each['text']))
        else:
            for e in each['fragments']:
                self.logger.info("failed to apply. \n\
                from_version: {}\n\
                to_version: {}\n\
                mother_function: {}\n\
                pattern_before: {}\n\
                pattern_behind: {}\n\
                replace: {}\n\
                text {}".format(e['from_version'], e['to_version'], e['mother_function'], e['pattern_before'], e['pattern_behind'], e['replace'], e['text']))
    
    def pattern_match(self, pattern_before, pattern_behind, replace, code, i):
        if i + 1 == len(code) and len(pattern_before) == 0:
            return False
        if len(replace) > 0:
            patterns = [pattern_before, replace, pattern_behind]
        else:
            patterns = [pattern_before, pattern_behind]

        for j in range(i, min(len(code), i+len(patterns))):
            if not sub_match(patterns[j-i], code[j]):
                return False
        return True

    def version_out_of_range(self, from_version, to_version, comp_version):
        res = False
        if from_version == "" and to_version == "":
            return res
        if from_version != "" and self.get_short_commit(from_version) == self.get_short_commit(comp_version):
            return res
        if from_version != "":
            if to_version == "":
                return not self.version_out_of_range(commit_v4_9, from_version, comp_version)
        else:
            from_version = commit_v4_9
        if self.key_in_table(from_version, to_version):
            return commit_tale[from_version][to_version]
        cmds = ["git", "rev-list", "^"+from_version, comp_version]
        r = subprocess.run(cmds, stdout=subprocess.PIPE, cwd=self.linux_path)
        lines = r.stdout.split(b'\n')
        # comp_version may earlier than from_version
        if len(lines) == 1 and lines[0] == b'':
            res = True
        for line in lines:
            line = line.decode("utf-8").strip('\n').strip('\r')
            if to_version in line:
                res = True
                break
        commit_tale[from_version][to_version] = res
        return res

    def key_in_table(self, from_version, to_version):
        if from_version not in commit_tale:
            commit_tale[from_version] = {}
        return to_version in commit_tale[from_version]
    
    def get_short_commit(self, commit):
        cmds = ["git log --oneline {} -n 1 | awk '{{print $1}}'".format(commit)]
        r = subprocess.run(cmds, stdout=subprocess.PIPE, cwd=self.linux_path, shell=True)
        lines = r.stdout.split(b'\n')
        line = lines[0].decode("utf-8").strip('\n').strip('\r')
        return line
    
if __name__ == '__main__':
    args = parse_args()
    if args.linux == None or args.patch == None:
        print("-linux and -patch cannot be None")
        exit(0)
    p = Patch(args.linux, args.patch)
    p.run()