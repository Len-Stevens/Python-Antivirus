import os

upper_dir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..'))

class Values():

    # current directory
    current_dir          = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..'))

    # app version
    app_version          = "3.1"

    # app log path
    app_log_path         = current_dir + "/logs/app_log.txt"

    # error log path
    error_log_path       = current_dir + "/logs/error_log.txt"

    # app ico path
    app_ico_path         = current_dir + "/res/ico/AntiVirus_ico.svg"

    # app settings path
    app_settings_path    = current_dir + "/settings/s.ini" 

    # app theme paths
    theme_path = current_dir + "/res/themes/"

    # app github links
    github_repo_link     = "https://github.com/cookie0o/Python-Antivirus-v2"
    github_issues_link   = "https://github.com/cookie0o/Python-Antivirus-v2/issues/new"

    # developers
    developers = {
        "cookie0_o",
        "Len-Stevens"
    }
    
    # style extra values
    extra = {
        # Density Scale
        'density_scale': '-1',
    }

    # known virus hashes paths
    MD5_HASHES_pack1     = current_dir + "/hashes/MD5_HASHES_pack1.txt"
    MD5_HASHES_pack2     = current_dir + "/hashes/MD5_HASHES_pack2.txt"
    MD5_HASHES_pack3     = current_dir + "/hashes/MD5_HASHES_pack3.txt"

    # Developers
    def app_developers():
        # join all developers into a string and return it
        devs = ", ".join(Values.developers)
        return devs