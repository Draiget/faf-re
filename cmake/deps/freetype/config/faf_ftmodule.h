/* The FreeType modules MSDF text links: the TrueType and CFF drivers and what they need. No Type 1,
 * PCF, BDF, WinFNT or SVG drivers, and no renderers, since the cook only reads outlines. */
FT_USE_MODULE( FT_Driver_ClassRec, tt_driver_class )
FT_USE_MODULE( FT_Driver_ClassRec, cff_driver_class )
FT_USE_MODULE( FT_Module_Class, psaux_module_class )
FT_USE_MODULE( FT_Module_Class, psnames_module_class )
FT_USE_MODULE( FT_Module_Class, pshinter_module_class )
FT_USE_MODULE( FT_Module_Class, sfnt_module_class )
