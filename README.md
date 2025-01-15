# LdapShot

GOALS:

Ldapper port with added features:
- Export results to file functionality
- Password Spraying Functionality
- Custom Query 
- Better Error Handling
- More default queries such as what Ldeep has


Ldeep
commands:
  available commands

  {auth_policies,bitlockerkeys,computers,conf,delegations,domain_policy,fsmo,gmsa,gpo,groups,machines,ou,pkis,pso,sccm,shadow_principals,silos,smsa,subnets,templates,trusts,users,zones,from_guid,from_sid,laps,memberships,membersof,object,sddl,silo,zone,all,enum_users,search,whoami,add_to_group,change_uac,create_computer,create_user,modify_password,remove_from_group,unlock}
    auth_policies       List the authentication policies configured in the Active Directory.
    bitlockerkeys       Extract the bitlocker recovery keys.
    computers           List the computer hostnames and resolve them if --resolve is specify.
    conf                Dump the configuration partition of the Active Directory.
    delegations         List accounts configured for any kind of delegation.
    domain_policy       Return the domain policy.
    fsmo                List FSMO roles.
    gmsa                List the gmsa accounts and retrieve secrets(NT + kerberos keys) if possible.
    gpo                 Return the list of Group policy objects.
    groups              List the groups.
    machines            List the machine accounts.
    ou                  Return the list of organizational units with linked GPO.
    pkis                List pkis.
    pso                 List the Password Settings Objects.
    sccm                List servers related to SCCM infrastructure (Primary/Secondary Sites and Distribution Points).
    shadow_principals   List the shadow principals and the groups associated with.
    silos               List the silos configured in the Active Directory.
    smsa                List the smsa accounts and the machines they are associated with.
    subnets             List sites and associated subnets.
    templates           List certificate templates.
    trusts              List the domain's trust relationships.
    users               List users according to a filter.
    zones               List the DNS zones configured in the Active Directory.
    from_guid           Return the object associated with the given `guid`.
    from_sid            Return the object associated with the given `sid`.
    laps                Return the LAPS passwords. If a target is specified, only retrieve the LAPS password for this one.
    memberships         List the group for which `account` belongs to.
    membersof           List the members of `group`.
    object              Return the records containing `object` in a CN.
    sddl                Returns the SDDL of an object given it's CN.
    silo                Get information about a specific `silo`.
    zone                Return the records of a DNS zone.
    all                 Collect and store computers, domain_policy, zones, gpo, groups, ou, users, trusts, pso information
    enum_users          Anonymously enumerate users with LDAP pings.
    search              Query the LDAP with `filter` and retrieve ALL or `attributes` if specified.
    whoami              Return user identity.
    add_to_group        Add `user` to `group`.
    change_uac          Change user account control
    create_computer     Create a computer account
    create_user         Create a user account
    modify_password     Change `user`'s password.
    remove_from_group   Remove `user` from `group`.
    unlock              Unlock `user`


## Getting started

Blah

## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://git.lab.local/DevOps/ldapshot.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://git.lab.local/DevOps/ldapshot/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
