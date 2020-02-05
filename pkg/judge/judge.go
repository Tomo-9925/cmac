package judge

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xapima/cmac/pkg/prof"
	"github.com/xapima/cmac/pkg/psutil"
	"github.com/xapima/conps/pkg/ps"
	"github.com/xapima/conps/pkg/util"
)

type JudgeApi struct {
	p     *prof.ProfApi
	allow *ruleCell
	deny  *ruleCell
}

type ruleCell struct {
	targetPath  map[string]uint
	childrenExe map[string]*ruleCell
	asterExe    map[string]*ruleCell
	// execPath    string
}

func newRuleCell() *ruleCell {
	t := make(map[string]uint)
	c := make(map[string]*ruleCell)
	a := make(map[string]*ruleCell)
	return &ruleCell{
		targetPath:  t,
		childrenExe: c,
		asterExe:    a,
		// execPath:    execPath,
	}
}

func NewJudgeApi(p *prof.ProfApi) *JudgeApi {
	a := newRuleCell()
	d := newRuleCell()
	j := &JudgeApi{
		p:     p,
		allow: a,
		deny:  d,
	}
	j.compileRules()
	return j

}

func (j *JudgeApi) Judge(filePath string, pid int, perm uint) (bool, error) {
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

	return true, nil
}

// httpd -> bash -> cat -> /etc/passwd は deny
// bash -> cat -> /etc/passwd は allow
// という条件の場合、ルールのロンゲストマッチを行う必要がある
// このためには、Pid 0 までルールを探索し、マッチしたルールを列挙する必要がある

func (j *JudgeApi) searchDeny(filePath string, pid int, perm uint) (bool, int, error) {
	// denyルールに抵触するとfalseを返す
	// 発見した深さも返す

	exeList, err := getAllExe(pid)
	if err != nil {
		return false, 0, util.ErrorWrapFunc(err)
	}
	cell := j.deny
	found, depth, err := cell.search(filePath, exeList, perm, -1)
	if err != nil {
		return false, -1, util.ErrorWrapFunc(err)
	}
	logrus.Debugf("DENY: found %v, depth %d", found, depth)

	return found, depth, nil
}

func (j *JudgeApi) searchAllow(filePath string, pid int, perm uint) (bool, int, error) {
	// allowルールに抵触するとtrueを返す
	// 発見した深さも返す

	exeList, err := getAllExe(pid)
	if err != nil {
		return false, 0, util.ErrorWrapFunc(err)
	}

	cell := j.allow
	found, depth, err := cell.search(filePath, exeList, perm, -1)
	if err != nil {
		return true, -1, util.ErrorWrapFunc(err)
	}

	return found, depth, nil
}

func (c *ruleCell) search(filePath string, exeList []string, perm uint, depth int) (bool, int, error) {
	logrus.Debugf("SERCH: exeList %v, depth %d, targetList %v", exeList, depth, c.targetPath)

	result := false
	cell := c
	resultDepth := -1

	if len(cell.targetPath) != 0 {
		if cperm, ok := cell.targetPath[filePath]; ok {
			if cperm&perm != 0 {
				logrus.Debug("deny found, depth:", depth)
				resultDepth = depth
				result = true
			}
		}
	}
	if len(exeList) != 0 {
		logrus.Debugf("len(exeList): %d", len(exeList))
		exe := exeList[0]
		if ncell, ok := cell.childrenExe[exe]; ok {
			logrus.Debug("search in childrenExe")
			ok, rDepth, err := ncell.search(filePath, exeList[1:], perm, depth+1)
			if err != nil {
				return false, -1, util.ErrorWrapFunc(err)
			}
			if ok {
				if resultDepth < rDepth {
					resultDepth = rDepth
					result = true
				}
			}
		}

		logrus.Debugf("asterExe: %v", cell.asterExe)
		for asterPath, asterCell := range cell.asterExe {
			logrus.Debugf("astarPath: %s", asterPath)
			for index, exePath := range exeList {
				logrus.Debugf("in aster: aster %s, exe %s", asterPath, exePath)
				if exePath == asterPath {
					ncell := asterCell
					ok, rDepth, err := ncell.search(filePath, exeList[1+index:], perm, depth+1)
					if err != nil {
						return false, -1, util.ErrorWrapFunc(err)
					}
					if ok {
						if resultDepth < rDepth {
							resultDepth = rDepth
							result = true
						}
					}
					// break
				}
			}
		}
	}
	return result, resultDepth, nil
}

func (j *JudgeApi) compileRules() {
	for exe, m := range j.p.Deny {
		logrus.Debug("NEW_RULE")
		for target, perm := range m {
			exeParts := strings.Split(exe, ",")
			cell := j.deny
			for i := len(exeParts) - 1; i >= 0; i-- {
				switch exeParts[i] {
				case "*":
					if i == 0 {
						break
					}
					i--
					if _, ok := cell.asterExe[exeParts[i]]; !ok {
						cell.asterExe[exeParts[i]] = newRuleCell()
					}
					logrus.Debugf("CELL nextExe %s: %v", exeParts[i], cell)
					cell = cell.asterExe[exeParts[i]]
				default:
					if _, ok := cell.childrenExe[exeParts[i]]; !ok {
						cell.childrenExe[exeParts[i]] = newRuleCell()
					}
					logrus.Debugf("CELL nextExe %s: %v", exeParts[i], cell)
					cell = cell.childrenExe[exeParts[i]]
				}
			}
			cell.targetPath[target] |= perm
			logrus.Debugf("CELL END exe %s, target %s : %v", exeParts[0], target, cell)
		}

	}

	for exe, m := range j.p.Allow {
		for target, perm := range m {
			exeParts := strings.Split(exe, ",")
			cell := j.allow
			for i := len(exeParts) - 1; i >= 0; i-- {
				switch exeParts[i] {
				case "*":
					if i == 0 {
						break
					}
					i--
					if _, ok := cell.asterExe[exeParts[i]]; !ok {
						cell.asterExe[exeParts[i]] = newRuleCell()
					}
					cell = cell.asterExe[exeParts[i]]
				default:
					if _, ok := cell.childrenExe[exeParts[i]]; !ok {
						cell.childrenExe[exeParts[i]] = newRuleCell()
					}
					cell = cell.childrenExe[exeParts[i]]
				}
				cell.targetPath[target] |= perm
			}
		}
	}
}

func getAllExe(pid int) ([]string, error) {
	out := make([]string, 0, 3)
	npid := pid
	for {
		if npid == 0 {
			break
		}
		exe, err := psutil.GetExePath(npid)
		if err != nil {
			return nil, util.ErrorWrapFunc(err)
		}
		out = append(out, exe)
		npid, err = ps.PPid(npid)
		logrus.Debugf("getAllExe npid: %d", npid)
		if err != nil {
			return nil, util.ErrorWrapFunc(err)
		}
	}
	return out, nil
}
