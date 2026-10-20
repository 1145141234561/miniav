/*
    worms.yar — 现代蠕虫检测规则草案（基于特征综述四层检测面）
    设计原则：只启用可静态验证、有明确误报边界的高置信锚点；
    漏洞利用前导（EXP blob）、Mirai telnet 爆破串等待样本实证后
    再转正（见 docs/worm_detection_draft.md 待实证清单）。
*/

/*
    凭证横移结构：SSH 私钥读取 + authorized_keys 写入/无确认连接。
    云蠕虫（TeamTNT/Rocke 系）通用结构：自动化脚本会关闭主机密钥
    确认以实现无人值守批量连接，正常管理员极少在脚本里固定此选项。
    已知误报面：配置管理工具（Ansible 等）模板可能包含同类串，
    需结合签名校验/路径上下文人工研判。
*/
rule Worm_SSH_Propagation
{
    meta:
        family = "Worm/SSH-CredSpread"
        level = "medium"
        source = "worm-draft"
        note = "凭据文件锚 + 自动化动作形态锚（写入重定向/sshpass），报告文本零误报"
    strings:
        $k1 = "id_rsa" ascii
        $k2 = "authorized_keys" ascii
        $x1 = "sshpass" ascii
        $x2 = />[^\n]{0,20}\.ssh\/authorized_keys/ ascii
        $x3 = /curl[^\n]{0,120}\|\s*sh/ ascii
    condition:
        1 of ($k*) and 1 of ($x*)
}

/*
    SMB 共享传播结构：管理共享路径 + 持久化动词（schtasks）。
    EternalBlue 后渗透、Zerologon 横移的经典路径：投放本体到
    \\ADMIN$ 后计划任务拉起。MZ 门限定 PE。
    已知误报面：PsExec/Sysinternals 类合法远管工具同样走
    ADMIN$+schtasks——由签名校验层豁免（签名有效不升级），
    规则层保持 medium 需人工研判。
*/
rule Worm_Share_Propagation
{
    meta:
        family = "Worm/SMB-Spread"
        level = "medium"
        source = "worm-draft"
        note = "管理共享 + 计划任务双锚；PsExec 类误报由签名豁免"
    strings:
        $s1 = "\\\\ADMIN$" ascii nocase
        $s2 = "\\\\C$" ascii nocase
        $x1 = "schtasks" ascii nocase
        $x2 = "at %02d:%02d" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($s*) and 1 of ($x*)
}

/*
    邮件蠕虫脚本结构：Outlook 自动化 + 自身作为附件群发。
    VBS 蠕虫（ILOVEYOU 结构）的现代变体仍保留此 API 组合；
    正常营销群发用 SMTP/SDK，不走 Outlook COM 自动化。
    filesize 门限制脚本体量，压制大文件误报。
*/
rule Worm_Email_Script
{
    meta:
        family = "Worm/Email-Spread"
        level = "medium"
        source = "worm-draft"
        note = "Outlook COM + 附件自群发组合；营销工具走 SMTP 不命中"
    strings:
        $o1 = "Outlook.Application" ascii nocase
        $m1 = ".Attachments.Add" ascii nocase
        $m2 = ".Recipients.Add" ascii nocase
    condition:
        filesize < 4MB and 1 of ($o*) and 1 of ($m*)
}
