"""Refresh the shared navigation in every template, then rebuild every generated report.

Run this after editing a template, site-map.json or a builder:

    python tools/build_all.py
    python tools/verify_report.py
"""
from build_af_report import main as build_af
from build_attributes_report import main as build_attributes
from build_colorspace_report import main as build_colorspace
from build_continuation_report import build_burn
from build_control_report import main as build_control
from build_deep_report import main as build_deep
from build_final_report import main as build_final
from build_foundation_report import main as build_foundation
from build_glyph_report import main as build_glyph
from build_implementation_report import main as build_implementation
from build_io_followup import build_loader
from build_lifecycle_report import main as build_lifecycle
from build_main_burn_report import main as build_main_burn
from build_nand_header_report import main as build_nand_headers
from build_nand_boot_read_report import main as build_nand_boot_read
from build_numeric_report import main as build_numeric
from build_pixel_report import main as build_pixel
from build_raster_report import main as build_raster
from build_render_report import main as build_render
from build_report import build_structure, main as build_index
from build_routing_report import main as build_routing
from build_task_report import main as build_task
from build_update_service_report import main as build_update_service
from site_chrome import main as refresh_navigation

BUILDERS = (
    build_index, build_structure, build_deep, build_routing, build_pixel, build_final, build_control, build_task,
    build_implementation, build_foundation, build_colorspace, build_numeric, build_lifecycle, build_af,
    build_loader, build_render, build_burn, build_raster, build_glyph, build_attributes,
    build_update_service, build_main_burn, build_nand_headers, build_nand_boot_read,
)


def main():
    refresh_navigation()
    for build in BUILDERS:
        build()


if __name__ == "__main__":
    main()
