import click
from vulners_yum_scanner.cli import pass_context
from vulners_yum_scanner.core import yum_audit


@click.command('audit', short_help='Audit a YUM repository')
@click.option('-r', '--repo', default='http://mirrors.kernel.org/centos/7/updates/x86_64/', show_default=True,
              type=click.STRING, help='YUM repo url')
@click.option('-o', '--os', default='centos', show_default=True,
              type=click.STRING, help="OS Family (e.g. 'centos'")
@click.option('-v', '--version', default='7', show_default=True,
              type=click.STRING, help='OS Version')
@pass_context
def cli(ctx, repo, os, version):
    """Audit Yum Repo against Vulners API"""
    _payload = {
        "repo": repo,
        "os": os,
        "version": version,
    }
    ctx.log('Starting Yum audit for: {data}'.format(data=_payload))

    auditor = yum_audit.yumAudit()
    auditor.audit(repo, os, version)
    # TODO - pull out and do printing here instead of deep in the core

