"""
Template loading and rendering for Binary Ninja Wrapped plugin.
"""
import os


def get_template_path(template_name):
    """Get the absolute path to a template file

    Args:
        template_name (str): Name of the template file

    Returns:
        str: Absolute path to the template file
    """
    # Get the directory where this module is located
    module_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(module_dir, 'templates')
    return os.path.join(templates_dir, template_name)


def load_template(template_name):
    """Load a template file from the templates directory

    Args:
        template_name (str): Name of the template file (e.g., 'stats_tab.html')

    Returns:
        str: Template content as string
    """
    template_path = get_template_path(template_name)
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()


def render_stats_tab(user_name, stats_quote, file_formats_html, formats_quote,
                     cpu_archs_html, archs_quote, binary_stats_html,
                     biggest_binary_html, static_count, dynamic_count,
                     static_quote, project_count, projects_quote, timestamp):
    """Render the stats tab HTML template

    Args:
        user_name (str): User's name
        stats_quote (str): Quote about overall stats
        file_formats_html (str): HTML for file formats list
        formats_quote (str): Quote about file formats
        cpu_archs_html (str): HTML for CPU architectures list
        archs_quote (str): Quote about architectures
        binary_stats_html (str): HTML for binary statistics
        biggest_binary_html (str): HTML for biggest binary info
        static_count (int): Number of static binaries
        dynamic_count (int): Number of dynamic binaries
        static_quote (str): Quote about static binaries
        project_count (int): Number of projects
        projects_quote (str): Quote about projects
        timestamp (str): Generation timestamp

    Returns:
        str: Rendered HTML
    """
    template = load_template('stats_tab.html')
    return template.format(
        user_name=user_name,
        stats_quote=stats_quote,
        file_formats=file_formats_html,
        formats_quote=formats_quote,
        cpu_archs=cpu_archs_html,
        archs_quote=archs_quote,
        binary_stats=binary_stats_html,
        biggest_binary=biggest_binary_html,
        static_count=static_count,
        dynamic_count=dynamic_count,
        static_quote=static_quote,
        project_count=project_count,
        projects_quote=projects_quote,
        timestamp=timestamp
    )


def render_export_html(css, date, overall_quote, binary_count, formats_quote,
                       file_formats_html, archs_quote, cpu_archs_html,
                       binary_stats_quote, binary_stats_html, biggest_binary_html,
                       static_quote, static_count, dynamic_count, user_name):
    """Render the export HTML template

    Args:
        css (str): CSS styles
        date (str): Generation date
        overall_quote (str): Quote about overall stats
        binary_count (int): Total number of binaries
        formats_quote (str): Quote about file formats
        file_formats_html (str): HTML for file formats list
        archs_quote (str): Quote about architectures
        cpu_archs_html (str): HTML for CPU architectures list
        binary_stats_quote (str): Quote about binary statistics
        binary_stats_html (str): HTML for binary statistics
        biggest_binary_html (str): HTML for biggest binary info
        static_quote (str): Quote about static binaries
        static_count (int): Number of static binaries
        dynamic_count (int): Number of dynamic binaries
        user_name (str): User's name

    Returns:
        str: Rendered HTML
    """
    template = load_template('export.html')
    return template.format(
        css=css,
        date=date,
        overall_quote=overall_quote,
        binary_count=binary_count,
        formats_quote=formats_quote,
        file_formats=file_formats_html,
        archs_quote=archs_quote,
        cpu_archs=cpu_archs_html,
        binary_stats_quote=binary_stats_quote,
        binary_stats=binary_stats_html,
        biggest_binary=biggest_binary_html,
        static_quote=static_quote,
        static_count=static_count,
        dynamic_count=dynamic_count,
        user_name=user_name
    )


def load_export_css():
    """Load the export CSS stylesheet

    Returns:
        str: CSS content
    """
    return load_template('export.css')
