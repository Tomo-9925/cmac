package judge

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xapima/cmac/pkg/prof"
	"github.com/xapima/conps/pkg/ps"
	"github.com/xapima/conps/pkg/util"
)

type JudgeApi struct {
	p     *prof.ProfApi
	allow map[string]*ruleCell
	deny  map[string]*ruleCell
}

type ruleCell struct {
	targetPath  map[string]int
	childrenExe map[string]*ruleCell
	// execPath    string
}

func newRuleCell() *ruleCell {
	t := make(map[string]int)
	c := make(map[string]*ruleCell)
	return &ruleCell{
		targetPath:  t,
		childrenExe: c,
		// execPath:    execPath,
	}
}

func NewJudgeApi(p *prof.ProfApi) *JudgeApi {

	a := make(map[string]*ruleCell)
	d := make(map[string]*ruleCell)

	j := &JudgeApi{
		p:     p,
		allow: a,
		deny:  d,
	}
	j.compileRules()
	return j

}

func (j *JudgeApi) Judge(filePath string, pid int, perm int) (bool, error) {
	// ファイルアクセスを許可しない場合はfalseを返す
	// denyルールに抵触するパターン
	// allowルールにexeStringは含まれており、そのcellのlen(targetPath)!=0 なのに、パスが含まれていない場合

	// denyルールのdepthとAllowルールのDepthを比較して、depthの深いほうが優先される
	// 両方のルールでdepthが-1の場合は、searchAllowNonSettingの結果を返す
	logrus.Debug("searchDeny")
	isDeny, denyDepth, err := j.searchDeny(filePath, pid, perm)
	if err != nil {
		return true, util.ErrorWrapFunc(err)
	}
	logrus.Infof("filePath: %s, isDeny: %v, denyDepth: %d", filePath, isDeny, denyDepth)

	logrus.Debug("searchAllow")
	isAllow, allowDepth, err := j.searchAllow(filePath, pid, perm)
	if err != nil {
		return true, util.ErrorWrapFunc(err)
	}
	logrus.Infof("filePath: %s, isAllow: %v, allowDepth: %d", filePath, isAllow, allowDepth)
	if isDeny && isAllow {
		if denyDepth >= allowDepth {
			return false, nil
		}
		return true, nil
	}
	if isDeny {
		return false, nil
	}
	if isAllow {
		return true, nil
	}

	// ok, err := j.searchAllowNonSetting(filePath, pid, perm)
	// if err != nil {
	// 	return true, util.ErrorWrapFunc(err)
	// }
	// return ok, nil
	return true, nil
}

// httpd -> bash -> cat -> /etc/passwd は deny
// bash -> cat -> /etc/passwd は allow
// という条件の場合、ルールのロンゲストマッチを行う必要がある
// このためには、Pid 0 までルールを探索し、マッチしたルールを列挙する必要がある

func (j *JudgeApi) searchDeny(filePath string, pid int, perm int) (bool, int, error) {
	// denyルールに抵触するとfalseを返す
	// 発見した深さも返す

	// exe, err := psutil.ExePath(pid)
	exe, err := ps.Exe(filepath.Join(proc, strconv.Itoa(pid)))
	if err != nil {
		return false, -1, util.ErrorWrapFunc(err)
	}
	if filePath == "/test/security/hello.sh" {
		logrus.Debugf("exe: %v", exe)
	}
	if _, ok := j.deny[exe]; !ok {
		logrus.Debug("non cell at first")
		return false, -1, nil
	}
	cell := j.deny[exe]
	found, depth, err := cell.search(filePath, pid, perm)
	if err != nil {
		return false, -1, util.ErrorWrapFunc(err)
	}
	return found, depth, nil
}

func (j *JudgeApi) searchAllow(filePath string, pid int, perm int) (bool, int, error) {
	// allowルールに抵触するとtrueを返す
	// 発見した深さも返す

	// exe, err := psutil.ExePath(pid)
	exe, err := ps.Exe(filepath.Join(proc, strconv.Itoa(pid)))
	if err != nil {
		return true, -1, util.ErrorWrapFunc(err)
	}
	if filePath == "/test/security/hello.sh" {
		logrus.Debugf("exe: %v", exe)
	}
	if _, ok := j.allow[exe]; !ok {
		return true, -1, nil
	}
	cell := j.allow[exe]
	found, depth, err := cell.search(filePath, pid, perm)
	if err != nil {
		return true, -1, util.ErrorWrapFunc(err)
	}
	return found, depth, nil

}

func (c *ruleCell) search(filePath string, pid int, perm int) (bool, int, error) {
	logrus.Debug("in search")
	var err error
	npid := pid
	resultDepth := -1
	depth := 1
	result := false
	cell := c
	for {
		logrus.Debug("npid: ", npid)
		if npid == 0 {
			break
		}
		if filePath == "/test/security/hello.sh" {
			logrus.Debugf("depth: %d", depth)
		}
		if len(cell.targetPath) != 0 {
			if cperm, ok := cell.targetPath[filePath]; ok {
				if cperm&perm != 0 {
					logrus.Debug("deny found, depth:", depth)
					resultDepth = depth
					result = true
				}
			}
		}
		npid, err = ps.PPid(npid)
		if err != nil {
			return result, resultDepth, util.ErrorWrapFunc(err)
		}
		if npid == 0 {
			break
		}
		// exe, err := psutil.ExePath(npid)
		exe, err := ps.Exe(filepath.Join(proc, strconv.Itoa(npid)))
		if err != nil {
			return result, resultDepth, util.ErrorWrapFunc(err)
		}
		if filePath == "/test/security/hello.sh" {
			logrus.Debugf("exe: %v", exe)
		}
		if _, ok := cell.childrenExe[exe]; !ok {
			logrus.Debug("cell not found")
			break
		}
		cell = cell.childrenExe[exe]
		depth++
	}
	return result, resultDepth, nil
}

// func (j *JudgeApi) searchAllowNonSetting(filePath string, pid int, perm int) (bool, error) {
// 	// allowルールにexeStringは含まれており、そのcellのlen(targetPath)!=0 なのにパスが含まれていない場合falseを返す
// 	npid := pid
// 	// exe, err := psutil.ExePath(npid)
// 	exe, err := ps.Exe(filepath.Join(proc, strconv.Itoa(npid)))
// 	if err != nil {
// 		return true, util.ErrorWrapFunc(err)
// 	}
// 	cell := j.deny[exe]
// 	result := true
// 	for {
// 		if npid == 0 {
// 			break
// 		}
// 		if len(cell.targetPath) != 0 {
// 			if cperm, ok := cell.targetPath[filePath]; !ok || (ok && cperm&perm == 0) {
// 				result = false
// 			}
// 		}
// 		npid, err = ps.PPid(pid)
// 		if err != nil {
// 			return result, util.ErrorWrapFunc(err)
// 		}
// 		if npid == 0 {
// 			break
// 		}
// 		// exe, err := psutil.ExePath(npid)
// 		exe, err := ps.Exe(filepath.Join(proc, strconv.Itoa(npid)))
// 		if err != nil {
// 			return result, util.ErrorWrapFunc(err)
// 		}
// 		if _, ok := cell.childrenExe[exe]; !ok {
// 			break
// 		}
// 		cell = cell.childrenExe[exe]
// 	}
// 	return result, nil
// }

func (j *JudgeApi) compileRules() {
	for exe, m := range j.p.Deny {
		for target, perm := range m {
			exeParts := strings.Split(exe, ",")
			lix := len(exeParts) - 1
			lstexe := exeParts[lix]
			if _, ok := j.deny[lstexe]; !ok {
				j.deny[lstexe] = newRuleCell()
			}
			cell := j.deny[lstexe]
			for i := lix; i > 0; i-- {
				nexe := exeParts[i-1]
				if _, ok := cell.childrenExe[nexe]; !ok {
					cell.childrenExe[nexe] = newRuleCell()
				}
				cell = cell.childrenExe[nexe]
			}
			cell.targetPath[target] = perm
		}
	}

	for exe, m := range j.p.Allow {
		for target, perm := range m {
			exeParts := strings.Split(exe, ",")
			lix := len(exeParts) - 1
			lstexe := exeParts[lix]
			if _, ok := j.allow[lstexe]; !ok {
				j.allow[lstexe] = newRuleCell()
			}
			cell := j.allow[lstexe]
			for i := lix; i > 0; i-- {
				nexe := exeParts[i-1]
				if _, ok := cell.childrenExe[nexe]; !ok {
					cell.childrenExe[nexe] = newRuleCell()
				}
				cell = cell.childrenExe[nexe]
			}
			cell.targetPath[target] = perm
		}
	}
}
