from django.conf.urls import url


def get_admin_urls(meta, admin_site, urls_add_info):
    return [url(
        f'^(?P<pk>.*)/{name}/$', admin_site.admin_view(
            view.as_view(admin_site=admin_site),
        ), name=f'{meta.app_label}_{meta.model_name}_{name}'
    ) for name, view in urls_add_info]
