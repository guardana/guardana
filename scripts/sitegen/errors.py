class SiteBuildError(Exception):
    """The site cannot be built from what is on disk, and will not be built partly.

    Every refusal in this package raises one of these rather than skipping the
    page it could not handle. A documentation site that silently drops a page is
    a page nobody notices is missing, which is the same failure as a check that
    silently does not run.
    """
