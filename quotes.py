"""
Quote and joke generation for Binary Ninja Wrapped plugin.
"""
import random
import operator


def get_stats_quote(count, user_name, binary_stats):
    """Get a quote about overall statistics

    Args:
        count (int): Number of binaries analyzed
        user_name (str): User's name
        binary_stats (dict): Dictionary with 'avg', 'min', 'max' keys

    Returns:
        str: A humorous quote about the statistics
    """
    quotes = [
        f"You've analyzed {count} binaries. That's more than most people analyze in a lifetime!",
        f"Your Binary Ninja has munched through {count} files. It's basically a digital gourmand.",
        f"If each binary was a step, you'd have walked {count} steps into the land of reverse engineering.",
        f"Your {count} binaries collectively take up {sum(binary_stats.values())/3:.2f} KB. That's like... a small picture of a cat.",
        f"Hey {user_name}, if reverse engineering were an Olympic sport, you'd be a contender with those {count} binaries!",
        f"Binary analysis level: {count}. Keep going {user_name}, you're doing great!",
        f"Your reverse engineering journey has taken you through {count} binaries. That's dedication!",
        f"Over {count} binaries analyzed - the machines are starting to worry about your skills.",
        f"With {count} files analyzed, you're officially a binary connoisseur.",
        f"Looking at {count} binaries? That's not just a hobby, that's a lifestyle choice.",
        f"The count is {count} binaries and rising! Your curiosity knows no bounds.",
        f"{user_name}, your binary collection of {count} files is impressive. Some people collect stamps, you collect binaries.",
    ]
    return random.choice(quotes)


def get_file_formats_quote(file_formats):
    """Get a quote about file format variety

    Args:
        file_formats (dict): Dictionary mapping format names to counts

    Returns:
        str: A humorous quote about the file formats
    """
    num_formats = len(file_formats)

    if num_formats == 0:
        return "No file formats detected? Do you even lift (binaries), bro?"
    elif num_formats == 1:
        format_name = next(iter(file_formats.keys()))
        quotes = [
            f"Just {format_name}? I see you're a person of focus, commitment, and sheer will.",
            f"100% {format_name} - that's what we call specialization in the binary world!",
            f"A {format_name} purist! There's something to be said for consistency.",
            f"When it comes to file formats, you've found your one true love: {format_name}.",
            f"You and {format_name} files - name a more iconic duo. I'll wait."
        ]
        return random.choice(quotes)
    elif num_formats == 2:
        formats = list(file_formats.keys())
        quotes = [
            "Two file formats - it's a binary situation in your binary analysis!",
            f"The {formats[0]} vs {formats[1]} battle continues...",
            "Two file formats walk into a bar... sounds like your typical workday.",
            f"Balancing between {formats[0]} and {formats[1]} like a digital tightrope walker.",
            "Your collection is like a tale of two formats - a binary binary."
        ]
        return random.choice(quotes)
    elif num_formats >= 3:
        # Get the top format
        top_format = sorted(file_formats.items(), key=operator.itemgetter(1), reverse=True)[0][0]
        quotes = [
            f"Variety is the spice of life! With {num_formats} different file formats, your binaries are having a format party.",
            f"Your file format diversity ({num_formats} types!) would make a biologist proud.",
            f"You've got {num_formats} different file formats - you're basically the UN of binary formats.",
            f"A particular fan of {top_format}, but with a healthy appreciation for {num_formats-1} other formats too.",
            f"Your binaries speak {num_formats} different dialects. You're a digital polyglot!",
            f"From {top_format} to {list(file_formats.keys())[-1]}, your format collection spans the binary alphabet."
        ]
        return random.choice(quotes)
    else:
        return "Your file formats are as diverse as a box of artisanal chocolates!"


def get_architectures_quote(cpu_archs):
    """Get a quote about CPU architecture variety

    Args:
        cpu_archs (dict): Dictionary mapping architecture names to counts

    Returns:
        str: A humorous quote about the architectures
    """
    num_archs = len(cpu_archs)

    if num_archs == 0:
        return "No architectures detected? Binary Ninja is more than just a hex-editor, you know."
    elif num_archs == 1:
        arch_name = next(iter(cpu_archs.keys()))
        quotes = [
            f"100% loyal to {arch_name}! When you find something you like, you stick with it.",
            f"A pure {arch_name} diet! The CPU architecture equivalent of a foodie with a favorite restaurant.",
            f"{arch_name} and you - a match made in silicon heaven.",
            f"The {arch_name} architecture fan club has exactly one member, and it's you!",
            f"All {arch_name}, all the time. Consistency is the hallmark of expertise.",
            f"You've got a special relationship with {arch_name}. It's not just an architecture, it's a lifestyle."
        ]
        return random.choice(quotes)
    elif num_archs == 2:
        archs = list(cpu_archs.keys())
        quotes = [
            "Two architectures - keeping one foot in each world. Perfectly balanced, as all things should be.",
            f"Splitting your time between {archs[0]} and {archs[1]}. Don't let them catch you stepping out!",
            f"{archs[0]} vs {archs[1]} - the eternal debate continues in your binary collection.",
            "Your architecture graph looks like a digital mullet: business in the front, party in the back.",
            f"A tale of two architectures: {archs[0]} and {archs[1]}. It was the best of code, it was the worst of code..."
        ]
        return random.choice(quotes)
    elif num_archs >= 3:
        # Get the top architecture
        top_arch = sorted(cpu_archs.items(), key=operator.itemgetter(1), reverse=True)[0][0]
        quotes = [
            f"With {num_archs} different architectures, you're basically the United Nations of binary analysis!",
            f"Your architecture diversity spans {num_archs} different instruction sets. Impressive!",
            f"From {top_arch} to {list(cpu_archs.keys())[-1]}, your CPU tastes are remarkably varied.",
            f"A {num_archs}-architecture polyglot! The Rosetta Stone of the binary world.",
            f"Your favorite? {top_arch}. But you've clearly got a soft spot for {num_archs-1} others too.",
            f"You've analyzed {num_archs} different architectures. That's like speaking {num_archs} different CPU languages!"
        ]
        return random.choice(quotes)
    else:
        return "I have no idea how you've managed this."


def get_binary_stats_quote(binary_stats):
    """Get a quote about binary statistics

    Args:
        binary_stats (dict): Dictionary with 'min size', 'max size', 'avg size' keys (in KB)

    Returns:
        str: A humorous quote about the binary size distribution
    """
    if binary_stats['min size'] == binary_stats['max size']:
        quotes = [
            "All your binaries are exactly the same size? That's more suspicious than identical twins with the same outfit.",
            "Same size binaries across the board. Either you're extremely consistent or something fishy is going on...",
            "Your binaries have found size equilibrium - like a digital zen garden.",
            f"Every binary is exactly {binary_stats['min size']:.1f}KB. Coincidence? I think not!",
            "The binary size inspector called: they want to know how you got them all exactly the same size."
        ]
        return random.choice(quotes)

    size_ratio = binary_stats['max size'] / max(1, binary_stats['min size'])

    if size_ratio > 100:
        quotes = [
            f"Your largest binary is {size_ratio:.1f}x bigger than your smallest. That's like comparing uhh, something huge to something tiny.",
            f"From tiny {binary_stats['min size']:.1f}KB to whopping {binary_stats['max size']:.1f}KB - that's a {size_ratio:.1f}x range!",
            f"Talk about size diversity! Your binaries range from microbe to whale ({size_ratio:.1f}x difference).",
            f"The binary size spectrum in your collection spans {size_ratio:.1f}x from smallest to largest. Impressive range!",
            f"Your binaries have serious size inequality issues - a {size_ratio:.1f}x gap between the haves and have-nots."
        ]
        return random.choice(quotes)
    elif size_ratio > 10:
        quotes = [
            f"From {binary_stats['min size']:.1f}KB to {binary_stats['max size']:.1f}KB - you've got quite the range there!",
            f"Your binary sizes span from {binary_stats['min size']:.1f}KB to {binary_stats['max size']:.1f}KB - that's versatility!",
            f"A {size_ratio:.1f}x difference between your smallest and largest binary. Not extreme, but definitely noteworthy.",
            f"Your average binary weighs in at {binary_stats['avg size']:.1f}KB - right in the Goldilocks zone!",
            f"Binary size range: {binary_stats['min size']:.1f}KB to {binary_stats['max size']:.1f}KB. A healthy ecosystem of code."
        ]
        return random.choice(quotes)
    else:
        quotes = [
            "Your binaries are surprisingly consistent in size. Marie Kondo would be proud of your tidy code.",
            f"With sizes ranging from {binary_stats['min size']:.1f}KB to {binary_stats['max size']:.1f}KB, your binaries are practically family.",
            "Your binary size distribution is tighter than a rock band's rhythm section.",
            f"Binary sizes all within a {size_ratio:.1f}x range - not much for variety, are you?",
            "Your binaries are like a well-designed set of nesting dolls - consistently proportioned.",
            f"Average size: {binary_stats['avg size']:.1f}KB. Remarkably consistent across the board!"
        ]
        return random.choice(quotes)


def get_static_binaries_quote(static_binaries_count):
    """Get a quote about static vs dynamic binaries

    Args:
        static_binaries_count (dict): Dictionary with 'static' and 'dynamic' keys

    Returns:
        str: A humorous quote about the static vs dynamic distribution
    """
    static_count = static_binaries_count['static']
    dynamic_count = static_binaries_count['dynamic']
    total = static_count + dynamic_count

    if total == 0:
        quotes = [
            "No binaries analyzed yet? The static vs dynamic debate awaits you!",
            "Static or dynamic, that is the question... that you haven't answered yet.",
            "The static/dynamic scoreboard is empty. Time to start analyzing!"
        ]
        return random.choice(quotes)

    static_percentage = (static_count / total * 100) if total > 0 else 0

    if static_percentage > 80:
        quotes = [
            "You're a static linking enthusiast! Your binaries are self-contained universes.",
            f"Static linking at {static_percentage:.1f}%! You really don't trust those system libraries, do you?",
            "Your binaries are like preppers - they've got everything they need packed inside.",
            f"With {static_count} static binaries, you're firmly in the 'package everything' camp.",
            "Static binaries dominate your collection. No dependency drama for you!",
            f"You're all about that static life: {static_percentage:.1f}% of your binaries are fully self-contained."
        ]
        return random.choice(quotes)
    elif static_percentage > 50:
        quotes = [
            "You prefer independence - most of your binaries are statically linked.",
            f"Slightly favoring static binaries ({static_percentage:.1f}%) - a cautious approach to dependencies.",
            f"Static wins over dynamic by {static_count} to {dynamic_count}. A narrow victory for self-sufficiency!",
            "Your binaries lean toward self-reliance, but you're not completely against sharing libraries.",
            f"With {static_percentage:.1f}% static binaries, you're mostly avoiding DLL hell."
        ]
        return random.choice(quotes)
    elif static_percentage > 20:
        quotes = [
            "A few static but mostly dynamic, I see.",
            f"Balanced approach: {static_count} static and {dynamic_count} dynamic binaries.",
            "Your static/dynamic distribution shows you appreciate both independence and efficiency.",
            f"With {static_percentage:.1f}% static binaries, you've found the middle path between isolation and integration.",
            "Some static, some dynamic - your binaries reflect a pragmatic approach to dependencies."
        ]
        return random.choice(quotes)
    else:
        quotes = [
            "You're all about those dynamic dependencies. Sharing is caring!",
            f"Dynamic linking enthusiast! {dynamic_count} of your {total} binaries share libraries.",
            "Your binaries are social creatures - they love sharing system libraries!",
            f"Only {static_percentage:.1f}% static binaries? You must really trust your runtime environment.",
            "Minimalist binaries are your style - why package what you can dynamically link?",
            f"With {dynamic_count} dynamic binaries, you're optimizing for size and update flexibility."
        ]
        return random.choice(quotes)


def get_projects_quote(project_count):
    """Get a quote about project usage

    Args:
        project_count (int): Number of Binary Ninja projects

    Returns:
        str: A humorous quote about project usage
    """
    if project_count == 0:
        quotes = [
            "No projects yet? Sometimes the best work happens directly in individual files!",
            "Flying solo without projects - a true minimalist approach.",
            "Zero projects detected. You're more of a 'one file at a time' kind of person.",
            "No projects? Maybe you're on non-commercial and those Vector 35 folks haven't been extra nice yet.",
        ]
    elif project_count == 1:
        quotes = [
            "One project! You're keeping things organized. That's the spirit!",
            "A single project shows focus and dedication to one task at a time.",
            "One project to rule them all! Quality over quantity.",
        ]
    elif project_count <= 3:
        quotes = [
            f"{project_count} projects! You're getting organized. We like it!",
            f"Working across {project_count} projects? Impressive multitasking!",
            f"With {project_count} projects, you're balancing multiple investigations nicely.",
        ]
    elif project_count <= 10:
        quotes = [
            f"{project_count} projects! Someone's staying organized. Are you using Enterprise?",
            f"Wow, {project_count} projects! Your organizational skills are on point.",
            f"Managing {project_count} projects like a pro! Enterprise features treating you well?",
            f"{project_count} projects in your recent files - you must have excellent taste in tools!",
        ]
    else:
        quotes = [
            f"{project_count} projects!? You're basically running a reverse engineering empire!",
            f"Holy organization, Batman! {project_count} projects shows serious dedication.",
            f"With {project_count} projects, you're definitely getting your money's worth from Enterprise!",
            f"{project_count} projects! You clearly appreciate the finer things in life, like proper project management.",
            f"The {project_count} projects in your recent files suggest you're a Binary Ninja power user. Respect!",
        ]

    return random.choice(quotes)
