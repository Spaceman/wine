#ifndef _WINE_D3D_H
#define _WINE_D3D_H

typedef LPVOID LPDIRECT3DMATERIAL,LPDIRECT3DVIEWPORT;
typedef LPVOID LPDIRECT3DMATERIAL2,LPDIRECT3DVIEWPORT2;
typedef LPVOID LPDIRECT3DDEVICE2;

DEFINE_GUID(IID_IDirect3D,		0x3BBA0080,0x2421,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID(IID_IDirect3D2,		0x6aae1ec1,0x662a,0x11d0,0x88,0x9d,0x00,0xaa,0x00,0xbb,0xb7,0x6a);

DEFINE_GUID(IID_IDirect3DRampDevice,	0xF2086B20,0x259F,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID(IID_IDirect3DRGBDevice,	0xA4665C60,0x2673,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56 );
DEFINE_GUID(IID_IDirect3DHALDevice,	0x84E63dE0,0x46AA,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E );
DEFINE_GUID(IID_IDirect3DMMXDevice,	0x881949a1,0xd6f3,0x11d0,0x89,0xab,0x00,0xa0,0xc9,0x05,0x41,0x29 );

DEFINE_GUID(IID_IDirect3DDevice,	0x64108800,0x957d,0x11D0,0x89,0xAB,0x00,0xA0,0xC9,0x05,0x41,0x29 );
DEFINE_GUID(IID_IDirect3DDevice2,	0x93281501,0x8CF8,0x11D0,0x89,0xAB,0x00,0xA0,0xC9,0x05,0x41,0x29);
DEFINE_GUID(IID_IDirect3DTexture,	0x2CDCD9E0,0x25A0,0x11CF,0xA3,0x1A,0x00,0xAA,0x00,0xB9,0x33,0x56);
DEFINE_GUID(IID_IDirect3DTexture2,	0x93281502,0x8CF8,0x11D0,0x89,0xAB,0x00,0xA0,0xC9,0x05,0x41,0x29);
DEFINE_GUID(IID_IDirect3DLight,		0x4417C142,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E);
DEFINE_GUID(IID_IDirect3DMaterial,	0x4417C144,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E);
DEFINE_GUID(IID_IDirect3DMaterial2,	0x93281503,0x8CF8,0x11D0,0x89,0xAB,0x00,0xA0,0xC9,0x05,0x41,0x29);
DEFINE_GUID(IID_IDirect3DExecuteBuffer,	0x4417C145,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E);
DEFINE_GUID(IID_IDirect3DViewport,	0x4417C146,0x33AD,0x11CF,0x81,0x6F,0x00,0x00,0xC0,0x20,0x15,0x6E);
DEFINE_GUID(IID_IDirect3DViewport2,	0x93281500,0x8CF8,0x11D0,0x89,0xAB,0x00,0xA0,0xC9,0x05,0x41,0x29);

typedef struct IDirect3D	IDirect3D ,*LPDIRECT3D ;
typedef struct IDirect3D2	IDirect3D2,*LPDIRECT3D2;
typedef struct IDirect3DLight	IDirect3DLight,*LPDIRECT3DLIGHT;

typedef struct {
	DWORD	dwSize;
	DWORD	dwCaps;
} D3DTRANSFORMCAPS,*LPD3DTRANSFORMCAPS;

#define D3DTRANSFORMCAPS_CLIP	0x00000001

typedef struct {
	DWORD	dwSize;
	DWORD	dwCaps;
	DWORD	dwLightingModel;
	DWORD	dwNumLights;
} D3DLIGHTINGCAPS, *LPD3DLIGHTINGCAPS;

#define D3DLIGHTINGMODEL_RGB		0x00000001
#define D3DLIGHTINGMODEL_MONO		0x00000002

#define D3DLIGHTCAPS_POINT		0x00000001
#define D3DLIGHTCAPS_SPOT		0x00000002
#define D3DLIGHTCAPS_DIRECTIONAL	0x00000004
#define D3DLIGHTCAPS_PARALLELPOINT	0x00000008


#define D3DCOLOR_MONO	1
#define D3DCOLOR_RGB	2

typedef DWORD D3DCOLORMODEL;

typedef struct {
    DWORD dwSize;
    DWORD dwMiscCaps;                 /* Capability flags */
    DWORD dwRasterCaps;
    DWORD dwZCmpCaps;
    DWORD dwSrcBlendCaps;
    DWORD dwDestBlendCaps;
    DWORD dwAlphaCmpCaps;
    DWORD dwShadeCaps;
    DWORD dwTextureCaps;
    DWORD dwTextureFilterCaps;
    DWORD dwTextureBlendCaps;
    DWORD dwTextureAddressCaps;
    DWORD dwStippleWidth;             /* maximum width and height of */
    DWORD dwStippleHeight;            /* of supported stipple (up to 32x32) */
} D3DPRIMCAPS, *LPD3DPRIMCAPS;

/* D3DPRIMCAPS.dwMiscCaps */
#define D3DPMISCCAPS_MASKPLANES		0x00000001
#define D3DPMISCCAPS_MASKZ		0x00000002
#define D3DPMISCCAPS_LINEPATTERNREP	0x00000004
#define D3DPMISCCAPS_CONFORMANT		0x00000008
#define D3DPMISCCAPS_CULLNONE		0x00000010
#define D3DPMISCCAPS_CULLCW		0x00000020
#define D3DPMISCCAPS_CULLCCW		0x00000040

/* D3DPRIMCAPS.dwRasterCaps */
#define D3DPRASTERCAPS_DITHER			0x00000001
#define D3DPRASTERCAPS_ROP2			0x00000002
#define D3DPRASTERCAPS_XOR			0x00000004
#define D3DPRASTERCAPS_PAT			0x00000008
#define D3DPRASTERCAPS_ZTEST			0x00000010
#define D3DPRASTERCAPS_SUBPIXEL			0x00000020
#define D3DPRASTERCAPS_SUBPIXELX		0x00000040
#define D3DPRASTERCAPS_FOGVERTEX		0x00000080
#define D3DPRASTERCAPS_FOGTABLE			0x00000100
#define D3DPRASTERCAPS_STIPPLE			0x00000200
#define D3DPRASTERCAPS_ANTIALIASSORTDEPENDENT	0x00000400
#define D3DPRASTERCAPS_ANTIALIASSORTINDEPENDENT	0x00000800
#define D3DPRASTERCAPS_ANTIALIASEDGES		0x00001000
#define D3DPRASTERCAPS_MIPMAPLODBIAS		0x00002000
#define D3DPRASTERCAPS_ZBIAS			0x00004000
#define D3DPRASTERCAPS_ZBUFFERLESSHSR		0x00008000
#define D3DPRASTERCAPS_FOGRANGE			0x00010000
#define D3DPRASTERCAPS_ANISOTROPY		0x00020000

/* D3DPRIMCAPS.dwZCmpCaps and dwAlphaCmpCaps */
#define D3DPCMPCAPS_NEVER		0x00000001
#define D3DPCMPCAPS_LESS		0x00000002
#define D3DPCMPCAPS_EQUAL		0x00000004
#define D3DPCMPCAPS_LESSEQUAL		0x00000008
#define D3DPCMPCAPS_GREATER		0x00000010
#define D3DPCMPCAPS_NOTEQUAL		0x00000020
#define D3DPCMPCAPS_GREATEREQUAL	0x00000040
#define D3DPCMPCAPS_ALWAYS		0x00000080

/* D3DPRIMCAPS.dwSourceBlendCaps, dwDestBlendCaps */
#define D3DPBLENDCAPS_ZERO		0x00000001
#define D3DPBLENDCAPS_ONE		0x00000002
#define D3DPBLENDCAPS_SRCCOLOR		0x00000004
#define D3DPBLENDCAPS_INVSRCCOLOR	0x00000008
#define D3DPBLENDCAPS_SRCALPHA		0x00000010
#define D3DPBLENDCAPS_INVSRCALPHA	0x00000020
#define D3DPBLENDCAPS_DESTALPHA		0x00000040
#define D3DPBLENDCAPS_INVDESTALPHA	0x00000080
#define D3DPBLENDCAPS_DESTCOLOR		0x00000100
#define D3DPBLENDCAPS_INVDESTCOLOR	0x00000200
#define D3DPBLENDCAPS_SRCALPHASAT	0x00000400
#define D3DPBLENDCAPS_BOTHSRCALPHA	0x00000800
#define D3DPBLENDCAPS_BOTHINVSRCALPHA	0x00001000

/* D3DPRIMCAPS.dwShadeCaps */
#define D3DPSHADECAPS_COLORFLATMONO	0x00000001
#define D3DPSHADECAPS_COLORFLATRGB	0x00000002
#define D3DPSHADECAPS_COLORGOURAUDMONO	0x00000004
#define D3DPSHADECAPS_COLORGOURAUDRGB	0x00000008
#define D3DPSHADECAPS_COLORPHONGMONO	0x00000010
#define D3DPSHADECAPS_COLORPHONGRGB	0x00000020

#define D3DPSHADECAPS_SPECULARFLATMONO	0x00000040
#define D3DPSHADECAPS_SPECULARFLATRGB	0x00000080
#define D3DPSHADECAPS_SPECULARGOURAUDMONO	0x00000100
#define D3DPSHADECAPS_SPECULARGOURAUDRGB	0x00000200
#define D3DPSHADECAPS_SPECULARPHONGMONO	0x00000400
#define D3DPSHADECAPS_SPECULARPHONGRGB	0x00000800

#define D3DPSHADECAPS_ALPHAFLATBLEND	0x00001000
#define D3DPSHADECAPS_ALPHAFLATSTIPPLED	0x00002000
#define D3DPSHADECAPS_ALPHAGOURAUDBLEND	0x00004000
#define D3DPSHADECAPS_ALPHAGOURAUDSTIPPLED	0x00008000
#define D3DPSHADECAPS_ALPHAPHONGBLEND	0x00010000
#define D3DPSHADECAPS_ALPHAPHONGSTIPPLED	0x00020000

#define D3DPSHADECAPS_FOGFLAT		0x00040000
#define D3DPSHADECAPS_FOGGOURAUD	0x00080000
#define D3DPSHADECAPS_FOGPHONG		0x00100000

/* D3DPRIMCAPS.dwTextureCaps */
#define D3DPTEXTURECAPS_PERSPECTIVE	0x00000001
#define D3DPTEXTURECAPS_POW2		0x00000002
#define D3DPTEXTURECAPS_ALPHA		0x00000004
#define D3DPTEXTURECAPS_TRANSPARENCY	0x00000008
#define D3DPTEXTURECAPS_BORDER		0x00000010
#define D3DPTEXTURECAPS_SQUAREONLY	0x00000020

/* D3DPRIMCAPS.dwTextureFilterCaps */
#define D3DPTFILTERCAPS_NEAREST		0x00000001
#define D3DPTFILTERCAPS_LINEAR		0x00000002
#define D3DPTFILTERCAPS_MIPNEAREST	0x00000004
#define D3DPTFILTERCAPS_MIPLINEAR	0x00000008
#define D3DPTFILTERCAPS_LINEARMIPNEAREST	0x00000010
#define D3DPTFILTERCAPS_LINEARMIPLINEAR	0x00000020

/* D3DPRIMCAPS.dwTextureBlendCaps */
#define D3DPTBLENDCAPS_DECAL		0x00000001
#define D3DPTBLENDCAPS_MODULATE		0x00000002
#define D3DPTBLENDCAPS_DECALALPHA	0x00000004
#define D3DPTBLENDCAPS_MODULATEALPHA	0x00000008
#define D3DPTBLENDCAPS_DECALMASK	0x00000010
#define D3DPTBLENDCAPS_MODULATEMASK	0x00000020
#define D3DPTBLENDCAPS_COPY		0x00000040
#define D3DPTBLENDCAPS_ADD		0x00000080

/* D3DPRIMCAPS.dwTextureAddressCaps */
#define D3DPTADDRESSCAPS_WRAP		0x00000001
#define D3DPTADDRESSCAPS_MIRROR		0x00000002
#define D3DPTADDRESSCAPS_CLAMP		0x00000004
#define D3DPTADDRESSCAPS_BORDER		0x00000008
#define D3DPTADDRESSCAPS_INDEPENDENTUV	0x00000010


/* D3DDEVICEDESC.dwFlags */
#define D3DDD_COLORMODEL		0x00000001
#define D3DDD_DEVCAPS			0x00000002
#define D3DDD_TRANSFORMCAPS		0x00000004
#define D3DDD_LIGHTINGCAPS		0x00000008
#define D3DDD_BCLIPPING			0x00000010
#define D3DDD_LINECAPS			0x00000020
#define D3DDD_TRICAPS			0x00000040
#define D3DDD_DEVICERENDERBITDEPTH	0x00000080
#define D3DDD_DEVICEZBUFFERBITDEPTH	0x00000100
#define D3DDD_MAXBUFFERSIZE		0x00000200
#define D3DDD_MAXVERTEXCOUNT		0x00000400

/* D3DDEVICEDESC.dwDevCaps */
#define D3DDEVCAPS_SORTINCREASINGZ      0x00000002
#define D3DDEVCAPS_SORTDECREASINGZ      0X00000004
#define D3DDEVCAPS_SORTEXACT            0x00000008
#define D3DDEVCAPS_EXECUTESYSTEMMEMORY  0x00000010
#define D3DDEVCAPS_EXECUTEVIDEOMEMORY   0x00000020
#define D3DDEVCAPS_TLVERTEXSYSTEMMEMORY 0x00000040
#define D3DDEVCAPS_TLVERTEXVIDEOMEMORY  0x00000080
#define D3DDEVCAPS_TEXTURESYSTEMMEMORY  0x00000100
#define D3DDEVCAPS_TEXTUREVIDEOMEMORY   0x00000200
#define D3DDEVCAPS_DRAWPRIMTLVERTEX     0x00000400
#define D3DDEVCAPS_CANRENDERAFTERFLIP   0x00000800
#define D3DDEVCAPS_TEXTURENONLOCALVIDMEM 0x00001000

typedef struct _D3DDeviceDesc {
	DWORD		dwSize;
	DWORD		dwFlags;
	D3DCOLORMODEL	dcmColorModel;
	DWORD		dwDevCaps;
	D3DTRANSFORMCAPS dtcTransformCaps;
	BOOL32		bClipping;
	D3DLIGHTINGCAPS	dlcLightingCaps;
	D3DPRIMCAPS	dpcLineCaps;
	D3DPRIMCAPS	dpcTriCaps;
	DWORD		dwDeviceRenderBitDepth;
	DWORD		dwDeviceZBufferBitDepth;
	DWORD		dwMaxBufferSize;
	DWORD		dwMaxVertexCount;
	/* *** New fields for DX5 *** */
	DWORD		dwMinTextureWidth,dwMinTextureHeight;
	DWORD		dwMaxTextureWidth,dwMaxTextureHeight;
	DWORD		dwMinStippleWidth,dwMaxStippleWidth;
	DWORD		dwMinStippleHeight,dwMaxStippleHeight;
} D3DDEVICEDESC,*LPD3DDEVICEDESC;
 
typedef HRESULT (CALLBACK * LPD3DENUMDEVICESCALLBACK)(LPGUID lpGuid,LPSTR lpDeviceDescription,LPSTR lpDeviceName,LPD3DDEVICEDESC,LPD3DDEVICEDESC,LPVOID);

/* dwflags for FindDevice */
#define D3DFDS_COLORMODEL		0x00000001
#define D3DFDS_GUID			0x00000002
#define D3DFDS_HARDWARE			0x00000004
#define D3DFDS_TRIANGLES		0x00000008
#define D3DFDS_LINES			0x00000010
#define D3DFDS_MISCCAPS			0x00000020
#define D3DFDS_RASTERCAPS		0x00000040
#define D3DFDS_ZCMPCAPS			0x00000080
#define D3DFDS_ALPHACMPCAPS		0x00000100
#define D3DFDS_DSTBLENDCAPS		0x00000400
#define D3DFDS_SHADECAPS		0x00000800
#define D3DFDS_TEXTURECAPS		0x00001000
#define D3DFDS_TEXTUREFILTERCAPS	0x00002000
#define D3DFDS_TEXTUREBLENDCAPS		0x00004000
#define D3DFDS_TEXTUREADDRESSCAPS	0x00008000

typedef struct {
    DWORD		dwSize;
    DWORD		dwFlags;
    BOOL32		bHardware;
    D3DCOLORMODEL	dcmColorModel;
    GUID		guid;
    DWORD		dwCaps;
    D3DPRIMCAPS		dpcPrimCaps;
} D3DFINDDEVICESEARCH,*LPD3DFINDDEVICESEARCH;

typedef struct {
    DWORD		dwSize;
    GUID		guid;
    D3DDEVICEDESC	ddHwDesc;
    D3DDEVICEDESC	ddSwDesc;
} D3DFINDDEVICERESULT,*LPD3DFINDDEVICERESULT;

#define D3DVALP(val, prec)	((float)(val))
#define D3DVAL(val)		((float)(val))
typedef float D3DVALUE,*LPD3DVALUE;
#define D3DDivide(a, b)		(float)((double) (a) / (double) (b))
#define D3DMultiply(a, b)	((a) * (b))

typedef struct {
	union {
		D3DVALUE x;
		D3DVALUE dvX;
	} x;
	union {
		D3DVALUE y;
		D3DVALUE dvY;
	} y;
	union {
		D3DVALUE z;
		D3DVALUE dvZ;
	} z;
	/* the c++ variant has operator overloads etc. too */
} D3DVECTOR,*LPD3DVECTOR;


typedef enum {
    D3DLIGHT_POINT          = 1,
    D3DLIGHT_SPOT           = 2,
    D3DLIGHT_DIRECTIONAL    = 3,
    D3DLIGHT_PARALLELPOINT  = 4,
    D3DLIGHT_FORCE_DWORD    = 0x7fffffff, /* force 32-bit size enum */
} D3DLIGHTTYPE;

typedef struct _D3DCOLORVALUE {
	union {
		D3DVALUE r;
		D3DVALUE dvR;
	} r;
	union {
		D3DVALUE g;
		D3DVALUE dvG;
	} g;
	union {
		D3DVALUE b;
		D3DVALUE dvB;
	} b;
	union {
		D3DVALUE a;
		D3DVALUE dvA;
	} a;
} D3DCOLORVALUE,*LPD3DCOLORVALUE;

typedef struct {
    DWORD           dwSize;
    D3DLIGHTTYPE    dltType;
    D3DCOLORVALUE   dcvColor;
    D3DVECTOR       dvPosition;		/* Position in world space */
    D3DVECTOR       dvDirection;	/* Direction in world space */
    D3DVALUE        dvRange;		/* Cutoff range */
    D3DVALUE        dvFalloff;		/* Falloff */
    D3DVALUE        dvAttenuation0;	/* Constant attenuation */
    D3DVALUE        dvAttenuation1;	/* Linear attenuation */
    D3DVALUE        dvAttenuation2;	/* Quadratic attenuation */
    D3DVALUE        dvTheta;		/* Inner angle of spotlight cone */
    D3DVALUE        dvPhi;		/* Outer angle of spotlight cone */
} D3DLIGHT,*LPD3DLIGHT;

/* flags bits */
#define D3DLIGHT_ACTIVE		0x00000001
#define D3DLIGHT_NO_SPECULAR	0x00000002


#define STDMETHOD(xfn) HRESULT (CALLBACK *fn##xfn)
#define STDMETHOD_(ret,xfn) ret (CALLBACK *fn##xfn)
#define PURE
#define FAR
#define THIS_ THIS ,

#define THIS LPDIRECT3D	this
typedef struct IDirect3D_VTable {
	/*** IUnknown methods ***/
	STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
	STDMETHOD_(ULONG, AddRef) (THIS) PURE;
	STDMETHOD_(ULONG, Release) (THIS) PURE;
	/*** IDirect3D methods ***/
	STDMETHOD(Initialize) (THIS_ REFIID) PURE;
	STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK, LPVOID) PURE;
	STDMETHOD(CreateLight) (THIS_ LPDIRECT3DLIGHT*, IUnknown*) PURE;
	STDMETHOD(CreateMaterial) (THIS_ LPDIRECT3DMATERIAL*, IUnknown*) PURE;
	STDMETHOD(CreateViewport) (THIS_ LPDIRECT3DVIEWPORT*, IUnknown*) PURE;
	STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) PURE;
} *LPDIRECT3D_VTABLE,IDirect3D_VTable;

struct IDirect3D {
	LPDIRECT3D_VTABLE	lpvtbl;
	DWORD			ref;
	LPDIRECTDRAW		ddraw;
};
#undef THIS

#define THIS LPDIRECT3D2 this
typedef struct IDirect3D2_VTable {
	/*** IUnknown methods ***/
	STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
	STDMETHOD_(ULONG, AddRef) (THIS) PURE;
	STDMETHOD_(ULONG, Release) (THIS) PURE;
	/*** IDirect3D2 methods ***/
	STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK, LPVOID) PURE;
	STDMETHOD(CreateLight) (THIS_ LPDIRECT3DLIGHT*, IUnknown*) PURE;
	STDMETHOD(CreateMaterial) (THIS_ LPDIRECT3DMATERIAL2*, IUnknown*) PURE;
	STDMETHOD(CreateViewport) (THIS_ LPDIRECT3DVIEWPORT2*, IUnknown*) PURE;
	STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) PURE;
	STDMETHOD(CreateDevice)(THIS_ REFCLSID, LPDIRECTDRAWSURFACE, LPDIRECT3DDEVICE2 *) PURE;
} *LPDIRECT3D2_VTABLE,IDirect3D2_VTable;

struct IDirect3D2 {
	LPDIRECT3D2_VTABLE	lpvtbl;
	DWORD			ref;
	LPDIRECTDRAW		ddraw;
};
#undef THIS

#define THIS LPDIRECT3DLIGHT this
typedef struct IDirect3DLight_VTable {
	/*** IUnknown methods ***/
	STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID* ppvObj) PURE;
	STDMETHOD_(ULONG, AddRef) (THIS) PURE;
	STDMETHOD_(ULONG, Release) (THIS) PURE;
	/*** IDirect3DLight methods ***/
	STDMETHOD(Initialize) (THIS_ LPDIRECT3D) PURE;
	STDMETHOD(SetLight) (THIS_ LPD3DLIGHT) PURE;
	STDMETHOD(GetLight) (THIS_ LPD3DLIGHT) PURE;
} IDirect3DLight_VTable,*LPDIRECT3DLIGHT_VTABLE;

struct IDirect3DLight {
	LPDIRECT3DLIGHT_VTABLE	lpvtbl;
	DWORD			ref;
};

#undef THIS

#undef THIS_
#undef STDMETHOD
#undef STDMETHOD_
#undef PURE
#undef FAR
#endif
