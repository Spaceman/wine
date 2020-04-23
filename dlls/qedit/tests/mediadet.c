/*
 * Unit tests for Media Detector
 *
 * Copyright (C) 2008 Google (Lei Zhang, Dan Hipschman)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS
#define CONST_VTABLE

#include "ole2.h"
#include "vfwmsgs.h"
#include "uuids.h"
#include "wine/strmbase.h"
#include "wine/test.h"
#include "qedit.h"
#include "control.h"
#include "rc.h"

static ULONG get_refcount(void *iface)
{
    IUnknown *unknown = iface;
    IUnknown_AddRef(unknown);
    return IUnknown_Release(unknown);
}

static const GUID test_iid = {0x33333333};
static LONG outer_ref = 1;

static HRESULT WINAPI outer_QueryInterface(IUnknown *iface, REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_IUnknown)
            || IsEqualGUID(iid, &IID_IMediaDet)
            || IsEqualGUID(iid, &test_iid))
    {
        *out = (IUnknown *)0xdeadbeef;
        return S_OK;
    }
    ok(0, "unexpected call %s\n", wine_dbgstr_guid(iid));
    return E_NOINTERFACE;
}

static ULONG WINAPI outer_AddRef(IUnknown *iface)
{
    return InterlockedIncrement(&outer_ref);
}

static ULONG WINAPI outer_Release(IUnknown *iface)
{
    return InterlockedDecrement(&outer_ref);
}

static const IUnknownVtbl outer_vtbl =
{
    outer_QueryInterface,
    outer_AddRef,
    outer_Release,
};

static IUnknown test_outer = {&outer_vtbl};

static void test_aggregation(void)
{
    IMediaDet *detector, *detector2;
    IUnknown *unk, *unk2;
    HRESULT hr;
    ULONG ref;

    detector = (IMediaDet *)0xdeadbeef;
    hr = CoCreateInstance(&CLSID_MediaDet, &test_outer, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (void **)&detector);
    ok(hr == E_NOINTERFACE, "Got hr %#x.\n", hr);
    ok(!detector, "Got interface %p.\n", detector);

    hr = CoCreateInstance(&CLSID_MediaDet, &test_outer, CLSCTX_INPROC_SERVER,
            &IID_IUnknown, (void **)&unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(outer_ref == 1, "Got unexpected refcount %d.\n", outer_ref);
    ok(unk != &test_outer, "Returned IUnknown should not be outer IUnknown.\n");
    ref = get_refcount(unk);
    ok(ref == 1, "Got unexpected refcount %d.\n", ref);

    ref = IUnknown_AddRef(unk);
    ok(ref == 2, "Got unexpected refcount %d.\n", ref);
    ok(outer_ref == 1, "Got unexpected refcount %d.\n", outer_ref);

    ref = IUnknown_Release(unk);
    ok(ref == 1, "Got unexpected refcount %d.\n", ref);
    ok(outer_ref == 1, "Got unexpected refcount %d.\n", outer_ref);

    hr = IUnknown_QueryInterface(unk, &IID_IUnknown, (void **)&unk2);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(unk2 == unk, "Got unexpected IUnknown %p.\n", unk2);
    IUnknown_Release(unk2);

    hr = IUnknown_QueryInterface(unk, &IID_IMediaDet, (void **)&detector);
    ok(hr == S_OK, "Got hr %#x.\n", hr);

    hr = IMediaDet_QueryInterface(detector, &IID_IUnknown, (void **)&unk2);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(unk2 == (IUnknown *)0xdeadbeef, "Got unexpected IUnknown %p.\n", unk2);

    hr = IMediaDet_QueryInterface(detector, &IID_IMediaDet, (void **)&detector2);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(detector2 == (IMediaDet *)0xdeadbeef, "Got unexpected IMediaDet %p.\n", detector2);

    hr = IUnknown_QueryInterface(unk, &test_iid, (void **)&unk2);
    ok(hr == E_NOINTERFACE, "Got hr %#x.\n", hr);
    ok(!unk2, "Got unexpected IUnknown %p.\n", unk2);

    hr = IMediaDet_QueryInterface(detector, &test_iid, (void **)&unk2);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(unk2 == (IUnknown *)0xdeadbeef, "Got unexpected IUnknown %p.\n", unk2);

    IMediaDet_Release(detector);
    ref = IUnknown_Release(unk);
    ok(!ref, "Got unexpected refcount %d.\n", ref);
    ok(outer_ref == 1, "Got unexpected refcount %d.\n", outer_ref);
}

struct testfilter
{
    struct strmbase_filter filter;
    struct strmbase_source source;
};

static inline struct testfilter *impl_from_strmbase_filter(struct strmbase_filter *iface)
{
    return CONTAINING_RECORD(iface, struct testfilter, filter);
}

static struct strmbase_pin *testfilter_get_pin(struct strmbase_filter *iface, unsigned int index)
{
    struct testfilter *filter = impl_from_strmbase_filter(iface);

    return index ? NULL : &filter->source.pin;
}

static void testfilter_destroy(struct strmbase_filter *iface)
{
    struct testfilter *filter = impl_from_strmbase_filter(iface);

    strmbase_source_cleanup(&filter->source);
    strmbase_filter_cleanup(&filter->filter);
}

static const struct strmbase_filter_ops testfilter_ops =
{
    .filter_get_pin = testfilter_get_pin,
    .filter_destroy = testfilter_destroy,
};

static HRESULT testsource_get_media_type(struct strmbase_pin *iface, unsigned int index, AM_MEDIA_TYPE *mt)
{
    static const VIDEOINFOHEADER source_format =
    {
        .bmiHeader.biSize = sizeof(BITMAPINFOHEADER),
        .bmiHeader.biWidth = 640,
        .bmiHeader.biHeight = 480,
        .bmiHeader.biPlanes = 1,
        .bmiHeader.biBitCount = 24,
        .bmiHeader.biCompression = BI_RGB,
        .bmiHeader.biSizeImage = 640 * 480 * 3
    };

    if (index)
        return S_FALSE;

    mt->majortype = MEDIATYPE_Video;
    mt->subtype = MEDIASUBTYPE_RGB24;
    mt->bFixedSizeSamples = TRUE;
    mt->bTemporalCompression = FALSE;
    mt->lSampleSize = source_format.bmiHeader.biSizeImage;
    mt->formattype = FORMAT_VideoInfo;
    mt->pUnk = NULL;
    mt->cbFormat = sizeof(source_format);
    mt->pbFormat = CoTaskMemAlloc(mt->cbFormat);
    memcpy(mt->pbFormat, &source_format, mt->cbFormat);
    return S_OK;
}

static HRESULT WINAPI testsource_DecideAllocator(struct strmbase_source *iface,
        IMemInputPin *peer, IMemAllocator **allocator)
{
    return S_OK;
}

static const struct strmbase_source_ops testsource_ops =
{
    .base.pin_get_media_type = testsource_get_media_type,
    .pfnAttemptConnection = BaseOutputPinImpl_AttemptConnection,
    .pfnDecideAllocator = testsource_DecideAllocator,
};

static void testfilter_init(struct testfilter *filter)
{
    static const GUID clsid = {0xabacab};

    memset(filter, 0, sizeof(*filter));
    strmbase_filter_init(&filter->filter, NULL, &clsid, &testfilter_ops);
    strmbase_source_init(&filter->source, &filter->filter, L"", &testsource_ops);
}

static WCHAR test_avi_filename[MAX_PATH];
static WCHAR test_sound_avi_filename[MAX_PATH];

static BOOL unpack_avi_file(int id, WCHAR name[MAX_PATH])
{
    static WCHAR temp_path[MAX_PATH];
    HRSRC res;
    HGLOBAL data;
    char *mem;
    DWORD size, written;
    HANDLE fh;
    BOOL ret;

    res = FindResourceW(NULL, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(AVI_RES_TYPE));
    if (!res)
        return FALSE;

    data = LoadResource(NULL, res);
    if (!data)
        return FALSE;

    mem = LockResource(data);
    if (!mem)
        return FALSE;

    size = SizeofResource(NULL, res);
    if (size == 0)
        return FALSE;

    if (!GetTempPathW(MAX_PATH, temp_path))
        return FALSE;

    /* We might end up relying on the extension here, so .TMP is no good.  */
    if (!GetTempFileNameW(temp_path, L"DES", 0, name))
        return FALSE;

    DeleteFileW(name);
    wcscpy(name + wcslen(name) - 3, L"avi");

    fh = CreateFileW(name, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE)
        return FALSE;

    ret = WriteFile(fh, mem, size, &written, NULL);
    CloseHandle(fh);
    return ret && written == size;
}

static BOOL init_tests(void)
{
    return unpack_avi_file(TEST_AVI_RES, test_avi_filename)
        && unpack_avi_file(TEST_SOUND_AVI_RES, test_sound_avi_filename);
}

static void test_mediadet(void)
{
    HRESULT hr;
    FILTER_INFO filter_info;
    AM_MEDIA_TYPE mt, *pmt;
    IEnumMediaTypes *type;
    IMediaDet *pM = NULL;
    BSTR filename = NULL;
    IBaseFilter *filter;
    IEnumPins *enumpins;
    LONG nstrms = 0;
    IUnknown *unk;
    IPin *pin;
    LONG strm;
    GUID guid;
    BSTR bstr;
    double fps;
    int flags;
    int i;

    /* test.avi has one video stream.  */
    hr = CoCreateInstance(&CLSID_MediaDet, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (LPVOID*)&pM);
    ok(hr == S_OK, "CoCreateInstance failed with %x\n", hr);
    ok(pM != NULL, "pM is NULL\n");

    filename = NULL;
    hr = IMediaDet_get_Filename(pM, &filename);
    /* Despite what MSDN claims, this returns S_OK.  */
    ok(hr == S_OK, "IMediaDet_get_Filename failed: %08x\n", hr);
    ok(filename == NULL, "IMediaDet_get_Filename\n");

    filename = (BSTR) -1;
    hr = IMediaDet_get_Filename(pM, &filename);
    /* Despite what MSDN claims, this returns S_OK.  */
    ok(hr == S_OK, "IMediaDet_get_Filename failed: %08x\n", hr);
    ok(filename == NULL, "IMediaDet_get_Filename\n");

    nstrms = -1;
    hr = IMediaDet_get_OutputStreams(pM, &nstrms);
    ok(hr == E_INVALIDARG, "IMediaDet_get_OutputStreams failed: %08x\n", hr);
    ok(nstrms == -1, "IMediaDet_get_OutputStreams: nstrms is %i\n", nstrms);

    strm = -1;
    /* The stream defaults to 0, even without a file!  */
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 0, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    hr = IMediaDet_get_CurrentStream(pM, NULL);
    ok(hr == E_POINTER, "IMediaDet_get_CurrentStream failed: %08x\n", hr);

    /* But put_CurrentStream doesn't.  */
    hr = IMediaDet_put_CurrentStream(pM, 0);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    hr = IMediaDet_put_CurrentStream(pM, -1);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    hr = IMediaDet_get_StreamMediaType(pM, &mt);
    ok(hr == E_INVALIDARG, "IMediaDet_get_StreamMediaType failed: %08x\n", hr);

    hr = IMediaDet_get_StreamMediaType(pM, NULL);
    ok(hr == E_POINTER, "IMediaDet_get_StreamMediaType failed: %08x\n", hr);

    hr = IMediaDet_get_StreamType(pM, &guid);
    ok(hr == E_INVALIDARG, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_StreamType(pM, NULL);
    ok(hr == E_POINTER, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_StreamTypeB(pM, &bstr);
    ok(hr == E_INVALIDARG, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_StreamTypeB(pM, NULL);
    ok(hr == E_INVALIDARG, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_Filter(pM, NULL);
    ok(hr == E_POINTER, "Got hr %#x.\n", hr);

    unk = (IUnknown*)0xdeadbeef;
    hr = IMediaDet_get_Filter(pM, &unk);
    ok(hr == S_FALSE, "Got hr %#x.\n", hr);
    ok(!unk, "Got filter %p.\n", unk);

    filename = SysAllocString(test_avi_filename);
    hr = IMediaDet_put_Filename(pM, filename);
    ok(hr == S_OK, "IMediaDet_put_Filename failed: %08x\n", hr);
    SysFreeString(filename);

    strm = -1;
    /* The stream defaults to 0.  */
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 0, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    ZeroMemory(&mt, sizeof mt);
    hr = IMediaDet_get_StreamMediaType(pM, &mt);
    ok(hr == S_OK, "IMediaDet_get_StreamMediaType failed: %08x\n", hr);
    CoTaskMemFree(mt.pbFormat);

    hr = IMediaDet_get_StreamType(pM, &guid);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(IsEqualGUID(&guid, &MEDIATYPE_Video), "Got major type %s.\n", debugstr_guid(&guid));

    hr = IMediaDet_get_StreamTypeB(pM, &bstr);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!wcscmp(bstr, L"{73646976-0000-0010-8000-00AA00389B71}"),
            "Got major type %s.\n", debugstr_w(bstr));
    SysFreeString(bstr);

    /* Even before get_OutputStreams.  */
    hr = IMediaDet_put_CurrentStream(pM, 1);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    hr = IMediaDet_get_OutputStreams(pM, &nstrms);
    ok(hr == S_OK, "IMediaDet_get_OutputStreams failed: %08x\n", hr);
    ok(nstrms == 1, "IMediaDet_get_OutputStreams: nstrms is %i\n", nstrms);

    filename = NULL;
    hr = IMediaDet_get_Filename(pM, &filename);
    ok(hr == S_OK, "IMediaDet_get_Filename failed: %08x\n", hr);
    ok(!wcscmp(filename, test_avi_filename), "Expected filename %s, got %s.\n",
            debugstr_w(test_avi_filename), debugstr_w(filename));
    SysFreeString(filename);

    hr = IMediaDet_get_Filename(pM, NULL);
    ok(hr == E_POINTER, "IMediaDet_get_Filename failed: %08x\n", hr);

    strm = -1;
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 0, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    hr = IMediaDet_get_CurrentStream(pM, NULL);
    ok(hr == E_POINTER, "IMediaDet_get_CurrentStream failed: %08x\n", hr);

    hr = IMediaDet_put_CurrentStream(pM, -1);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    hr = IMediaDet_put_CurrentStream(pM, 1);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    /* Try again.  */
    strm = -1;
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 0, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    hr = IMediaDet_put_CurrentStream(pM, 0);
    ok(hr == S_OK, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    strm = -1;
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 0, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    ZeroMemory(&mt, sizeof mt);
    hr = IMediaDet_get_StreamMediaType(pM, &mt);
    ok(hr == S_OK, "IMediaDet_get_StreamMediaType failed: %08x\n", hr);
    ok(IsEqualGUID(&mt.majortype, &MEDIATYPE_Video),
                 "IMediaDet_get_StreamMediaType\n");
    CoTaskMemFree(mt.pbFormat);

    hr = IMediaDet_get_StreamType(pM, &guid);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(IsEqualGUID(&guid, &MEDIATYPE_Video), "Got major type %s.\n", debugstr_guid(&guid));

    hr = IMediaDet_get_StreamTypeB(pM, &bstr);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!wcscmp(bstr, L"{73646976-0000-0010-8000-00AA00389B71}"),
            "Got major type %s.\n", debugstr_w(bstr));
    SysFreeString(bstr);

    hr = IMediaDet_get_FrameRate(pM, NULL);
    ok(hr == E_POINTER, "IMediaDet_get_FrameRate failed: %08x\n", hr);

    hr = IMediaDet_get_FrameRate(pM, &fps);
    ok(hr == S_OK, "IMediaDet_get_FrameRate failed: %08x\n", hr);
    ok(fps == 10.0, "IMediaDet_get_FrameRate: fps is %f\n", fps);

    hr = IMediaDet_Release(pM);
    ok(hr == 0, "IMediaDet_Release returned: %x\n", hr);

    /* test_sound.avi has one video stream and one audio stream.  */
    hr = CoCreateInstance(&CLSID_MediaDet, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (LPVOID*)&pM);
    ok(hr == S_OK, "CoCreateInstance failed with %x\n", hr);
    ok(pM != NULL, "pM is NULL\n");

    filename = SysAllocString(test_sound_avi_filename);
    hr = IMediaDet_put_Filename(pM, filename);
    ok(hr == S_OK, "IMediaDet_put_Filename failed: %08x\n", hr);
    SysFreeString(filename);

    hr = IMediaDet_get_OutputStreams(pM, &nstrms);
    ok(hr == S_OK, "IMediaDet_get_OutputStreams failed: %08x\n", hr);
    ok(nstrms == 2, "IMediaDet_get_OutputStreams: nstrms is %i\n", nstrms);

    filename = NULL;
    hr = IMediaDet_get_Filename(pM, &filename);
    ok(hr == S_OK, "IMediaDet_get_Filename failed: %08x\n", hr);
    ok(!wcscmp(filename, test_sound_avi_filename), "Expected filename %s, got %s.\n",
            debugstr_w(test_sound_avi_filename), debugstr_w(filename));
    SysFreeString(filename);

    /* I don't know if the stream order is deterministic.  Just check
       for both an audio and video stream.  */
    flags = 0;

    for (i = 0; i < 2; ++i)
    {
        hr = IMediaDet_put_CurrentStream(pM, i);
        ok(hr == S_OK, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

        strm = -1;
        hr = IMediaDet_get_CurrentStream(pM, &strm);
        ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
        ok(strm == i, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

        ZeroMemory(&mt, sizeof mt);
        hr = IMediaDet_get_StreamMediaType(pM, &mt);
        ok(hr == S_OK, "IMediaDet_get_StreamMediaType failed: %08x\n", hr);
        flags += (IsEqualGUID(&mt.majortype, &MEDIATYPE_Video)
                  ? 1
                  : (IsEqualGUID(&mt.majortype, &MEDIATYPE_Audio)
                     ? 2
                     : 0));

        if (IsEqualGUID(&mt.majortype, &MEDIATYPE_Audio))
        {
            hr = IMediaDet_get_StreamType(pM, &guid);
            ok(hr == S_OK, "Got hr %#x.\n", hr);
            ok(IsEqualGUID(&guid, &MEDIATYPE_Audio), "Got major type %s.\n", debugstr_guid(&guid));

            hr = IMediaDet_get_StreamTypeB(pM, &bstr);
            ok(hr == S_OK, "Got hr %#x.\n", hr);
            ok(!wcscmp(bstr, L"{73647561-0000-0010-8000-00AA00389B71}"),
                    "Got major type %s.\n", debugstr_w(bstr));
            SysFreeString(bstr);

            hr = IMediaDet_get_FrameRate(pM, &fps);
            ok(hr == VFW_E_INVALIDMEDIATYPE, "IMediaDet_get_FrameRate failed: %08x\n", hr);
        }

        CoTaskMemFree(mt.pbFormat);
    }
    ok(flags == 3, "IMediaDet_get_StreamMediaType: flags are %i\n", flags);

    hr = IMediaDet_put_CurrentStream(pM, 2);
    ok(hr == E_INVALIDARG, "IMediaDet_put_CurrentStream failed: %08x\n", hr);

    strm = -1;
    hr = IMediaDet_get_CurrentStream(pM, &strm);
    ok(hr == S_OK, "IMediaDet_get_CurrentStream failed: %08x\n", hr);
    ok(strm == 1, "IMediaDet_get_CurrentStream: strm is %i\n", strm);

    unk = NULL;
    hr = IMediaDet_get_Filter(pM, &unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!!unk, "Expected a non-NULL filter.\n");
    hr = IUnknown_QueryInterface(unk, &IID_IBaseFilter, (void**)&filter);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    IUnknown_Release(unk);

    hr = IBaseFilter_EnumPins(filter, &enumpins);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    hr = IEnumPins_Next(enumpins, 1, &pin, NULL);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    hr = IPin_EnumMediaTypes(pin, &type);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    hr = IEnumMediaTypes_Next(type, 1, &pmt, NULL);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(IsEqualGUID(&pmt->majortype, &MEDIATYPE_Stream), "Got major type %s.\n",
            debugstr_guid(&pmt->majortype));
    IEnumMediaTypes_Release(type);
    CoTaskMemFree(pmt->pbFormat);
    CoTaskMemFree(pmt);
    IPin_Release(pin);

    hr = IEnumPins_Next(enumpins, 1, &pin, NULL);
    ok(hr == S_FALSE, "Got hr %#x.\n", hr);
    IEnumPins_Release(enumpins);

    hr = IBaseFilter_QueryFilterInfo(filter, &filter_info);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!wcscmp(filter_info.achName, L"Source"), "Got name %s.\n", debugstr_w(filter_info.achName));
    IFilterGraph_Release(filter_info.pGraph);
    IBaseFilter_Release(filter);

    hr = IMediaDet_Release(pM);
    ok(hr == 0, "IMediaDet_Release returned: %x\n", hr);
}

static void test_put_filter(void)
{
    struct testfilter testfilter, testfilter2;
    IFilterGraph *graph;
    IBaseFilter *filter;
    IMediaDet *detector;
    LONG index, count;
    AM_MEDIA_TYPE mt;
    IUnknown *unk;
    BSTR filename;
    HRESULT hr;
    ULONG ref;

    hr = CoCreateInstance(&CLSID_MediaDet, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (void **)&detector);
    ok(hr == S_OK, "Got hr %#x.\n", hr);

    hr = IMediaDet_put_Filter(detector, NULL);
    ok(hr == E_POINTER, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_Filter(detector, NULL);
    ok(hr == E_POINTER, "Got hr %#x.\n", hr);

    testfilter_init(&testfilter);
    hr = IMediaDet_put_Filter(detector, &testfilter.filter.IUnknown_inner);
    ok(hr == S_OK, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_Filter(detector, &unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!!unk, "Expected a non-NULL interface.\n");
    hr = IUnknown_QueryInterface(unk, &IID_IBaseFilter, (void **)&filter);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(filter == &testfilter.filter.IBaseFilter_iface, "Expected the same filter.\n");
    IBaseFilter_Release(filter);
    IUnknown_Release(unk);

    ok(!wcscmp(testfilter.filter.name, L"Source"), "Got name %s.\n",
            debugstr_w(testfilter.filter.name));
    graph = testfilter.filter.graph;
    IFilterGraph_AddRef(graph);

    testfilter_init(&testfilter2);
    hr = IMediaDet_put_Filter(detector, &testfilter2.filter.IUnknown_inner);
    ok(hr == S_OK, "Got hr %#x.\n", hr);

    hr = IMediaDet_get_Filter(detector, &unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!!unk, "Expected a non-NULL interface.\n");
    hr = IUnknown_QueryInterface(unk, &IID_IBaseFilter, (void **)&filter);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(filter == &testfilter2.filter.IBaseFilter_iface, "Expected the same filter.\n");
    IBaseFilter_Release(filter);
    IUnknown_Release(unk);

    ok(testfilter2.filter.graph != graph, "Expected a different graph.\n");

    ref = IFilterGraph_Release(graph);
    ok(!ref, "Got outstanding refcount %d.\n", ref);
    ref = IBaseFilter_Release(&testfilter.filter.IBaseFilter_iface);
    ok(!ref, "Got outstanding refcount %d.\n", ref);

    count = 0xdeadbeef;
    hr = IMediaDet_get_OutputStreams(detector, &count);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(count == 1, "Got %d streams.\n", count);

    index = 0xdeadbeef;
    hr = IMediaDet_get_CurrentStream(detector, &index);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(index == 0, "Got stream %d.\n", index);

    filename = (BSTR)0xdeadbeef;
    hr = IMediaDet_get_Filename(detector, &filename);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!filename, "Got filename %s.\n", debugstr_w(filename));

    ref = IMediaDet_Release(detector);
    ok(!ref, "Got outstanding refcount %d.\n", ref);
    ref = IBaseFilter_Release(&testfilter2.filter.IBaseFilter_iface);
    ok(!ref, "Got outstanding refcount %d.\n", ref);

    hr = CoCreateInstance(&CLSID_MediaDet, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (void **)&detector);
    ok(hr == S_OK, "Got hr %#x.\n", hr);

    filename = SysAllocString(test_sound_avi_filename);
    hr = IMediaDet_put_Filename(detector, filename);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    SysFreeString(filename);

    hr = IMediaDet_get_StreamMediaType(detector, &mt);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    FreeMediaType(&mt);

    hr = IMediaDet_get_Filter(detector, &unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    hr = IMediaDet_put_Filter(detector, unk);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    IUnknown_Release(unk);

    filename = (BSTR)0xdeadbeef;
    hr = IMediaDet_get_Filename(detector, &filename);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(!filename, "Got filename %s.\n", debugstr_w(filename));

    count = 0xdeadbeef;
    hr = IMediaDet_get_OutputStreams(detector, &count);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(count == 2, "Got %d streams.\n", count);

    index = 0xdeadbeef;
    hr = IMediaDet_get_CurrentStream(detector, &index);
    ok(hr == S_OK, "Got hr %#x.\n", hr);
    ok(index == 0, "Got stream %d.\n", index);

    ref = IMediaDet_Release(detector);
    ok(!ref, "Got outstanding refcount %d.\n", ref);
}

static HRESULT WINAPI ms_QueryInterface(IMediaSample *iface, REFIID riid,
        void **ppvObject)
{
    return E_NOTIMPL;
}

static ULONG WINAPI ms_AddRef(IMediaSample *iface)
{
    return 2;
}

static ULONG WINAPI ms_Release(IMediaSample *iface)
{
    return 1;
}

static HRESULT WINAPI ms_GetPointer(IMediaSample *iface, BYTE **ppBuffer)
{
    return E_NOTIMPL;
}

static LONG WINAPI ms_GetSize(IMediaSample *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_GetTime(IMediaSample *iface, REFERENCE_TIME *pTimeStart,
        REFERENCE_TIME *pTimeEnd)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetTime(IMediaSample *iface, REFERENCE_TIME *pTimeStart,
        REFERENCE_TIME *pTimeEnd)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_IsSyncPoint(IMediaSample *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetSyncPoint(IMediaSample *iface, BOOL bIsSyncPoint)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_IsPreroll(IMediaSample *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetPreroll(IMediaSample *iface, BOOL bIsPreroll)
{
    return E_NOTIMPL;
}

static LONG WINAPI ms_GetActualDataLength(IMediaSample *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetActualDataLength(IMediaSample *iface, LONG length)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_GetMediaType(IMediaSample *iface, AM_MEDIA_TYPE
        **ppMediaType)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetMediaType(IMediaSample *iface, AM_MEDIA_TYPE *pMediaType)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_IsDiscontinuity(IMediaSample *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetDiscontinuity(IMediaSample *iface, BOOL bDiscontinuity)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_GetMediaTime(IMediaSample *iface, LONGLONG *pTimeStart,
        LONGLONG *pTimeEnd)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI ms_SetMediaTime(IMediaSample *iface, LONGLONG *pTimeStart,
        LONGLONG *pTimeEnd)
{
    return E_NOTIMPL;
}

static const IMediaSampleVtbl my_sample_vt = {
    ms_QueryInterface,
    ms_AddRef,
    ms_Release,
    ms_GetPointer,
    ms_GetSize,
    ms_GetTime,
    ms_SetTime,
    ms_IsSyncPoint,
    ms_SetSyncPoint,
    ms_IsPreroll,
    ms_SetPreroll,
    ms_GetActualDataLength,
    ms_SetActualDataLength,
    ms_GetMediaType,
    ms_SetMediaType,
    ms_IsDiscontinuity,
    ms_SetDiscontinuity,
    ms_GetMediaTime,
    ms_SetMediaTime
};

static IMediaSample my_sample = { &my_sample_vt };

static BOOL samplecb_called = FALSE;

static HRESULT WINAPI sgcb_QueryInterface(ISampleGrabberCB *iface, REFIID riid,
        void **ppvObject)
{
    return E_NOTIMPL;
}

static ULONG WINAPI sgcb_AddRef(ISampleGrabberCB *iface)
{
    return E_NOTIMPL;
}

static ULONG WINAPI sgcb_Release(ISampleGrabberCB *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI sgcb_SampleCB(ISampleGrabberCB *iface, double SampleTime,
        IMediaSample *pSample)
{
    ok(pSample == &my_sample, "Got wrong IMediaSample: %p, expected %p\n", pSample, &my_sample);
    samplecb_called = TRUE;
    return E_NOTIMPL;
}

static HRESULT WINAPI sgcb_BufferCB(ISampleGrabberCB *iface, double SampleTime,
        BYTE *pBuffer, LONG BufferLen)
{
    ok(0, "BufferCB should not have been called\n");
    return E_NOTIMPL;
}

static const ISampleGrabberCBVtbl sgcb_vt = {
    sgcb_QueryInterface,
    sgcb_AddRef,
    sgcb_Release,
    sgcb_SampleCB,
    sgcb_BufferCB
};

static ISampleGrabberCB my_sg_cb = { &sgcb_vt };

static void test_samplegrabber(void)
{
    ISampleGrabber *sg;
    IBaseFilter *bf;
    IPin *pin;
    IMemInputPin *inpin;
    IEnumPins *pins;
    HRESULT hr;
    FILTER_STATE fstate;

    /* Invalid RIID */
    hr = CoCreateInstance(&CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, &IID_IClassFactory,
            (void**)&sg);
    ok(hr == E_NOINTERFACE, "SampleGrabber create failed: %08x, expected E_NOINTERFACE\n", hr);

    hr = CoCreateInstance(&CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, &IID_ISampleGrabber,
            (void**)&sg);
    ok(hr == S_OK, "SampleGrabber create failed: %08x, expected S_OK\n", hr);

    hr = ISampleGrabber_QueryInterface(sg, &IID_IBaseFilter, (void**)&bf);
    ok(hr == S_OK, "QueryInterface for IID_IBaseFilter failed: %08x\n", hr);

    hr = ISampleGrabber_SetCallback(sg, &my_sg_cb, 0);
    ok(hr == S_OK, "SetCallback failed: %08x\n", hr);

    hr = IBaseFilter_GetState(bf, 100, &fstate);
    ok(hr == S_OK, "Failed to get filter state: %08x\n", hr);
    ok(fstate == State_Stopped, "Got wrong filter state: %u\n", fstate);

    hr = IBaseFilter_EnumPins(bf, &pins);
    ok(hr == S_OK, "EnumPins create failed: %08x, expected S_OK\n", hr);

    hr = IEnumPins_Next(pins, 1, &pin, NULL);
    ok(hr == S_OK, "Next failed: %08x\n", hr);

    IEnumPins_Release(pins);

    hr = IPin_QueryInterface(pin, &IID_IMemInputPin, (void**)&inpin);
    ok(hr == S_OK, "QueryInterface(IMemInputPin) failed: %08x\n", hr);

    hr = IMemInputPin_Receive(inpin, &my_sample);
    ok(hr == S_OK, "Receive failed: %08x\n", hr);
    ok(samplecb_called == TRUE, "SampleCB should have been called\n");

    IMemInputPin_Release(inpin);
    IPin_Release(pin);

    while (ISampleGrabber_Release(sg));
}

static void test_COM_sg_enumpins(void)
{
    IBaseFilter *bf;
    IEnumPins *pins, *pins2;
    IUnknown *unk;
    ULONG refcount;
    HRESULT hr;

    hr = CoCreateInstance(&CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, &IID_IBaseFilter,
            (void**)&bf);
    ok(hr == S_OK, "SampleGrabber create failed: %08x, expected S_OK\n", hr);
    hr = IBaseFilter_EnumPins(bf, &pins);
    ok(hr == S_OK, "EnumPins create failed: %08x, expected S_OK\n", hr);

    /* Same refcount for all EnumPins interfaces */
    refcount = IEnumPins_AddRef(pins);
    ok(refcount == 2, "refcount == %u, expected 2\n", refcount);
    hr = IEnumPins_QueryInterface(pins, &IID_IEnumPins, (void**)&pins2);
    ok(hr == S_OK, "QueryInterface for IID_IEnumPins failed: %08x\n", hr);
    ok(pins == pins2, "QueryInterface for self failed (%p != %p)\n", pins, pins2);
    IEnumPins_Release(pins2);

    hr = IEnumPins_QueryInterface(pins, &IID_IUnknown, (void**)&unk);
    ok(hr == S_OK, "QueryInterface for IID_IUnknown failed: %08x\n", hr);
    refcount = IUnknown_AddRef(unk);
    ok(refcount == 4, "refcount == %u, expected 4\n", refcount);
    refcount = IUnknown_Release(unk);

    while (IEnumPins_Release(pins));
    IBaseFilter_Release(bf);
}

START_TEST(mediadet)
{
    IMediaDet *detector;
    HRESULT hr;
    BOOL ret;

    if (!init_tests())
    {
        skip("Couldn't initialize tests!\n");
        return;
    }

    CoInitialize(NULL);

    if (FAILED(hr = CoCreateInstance(&CLSID_MediaDet, NULL, CLSCTX_INPROC_SERVER,
            &IID_IMediaDet, (void **)&detector)))
    {
        /* qedit.dll does not exist on 2003. */
        win_skip("Failed to create media detector object, hr %#x.\n", hr);
        return;
    }
    IMediaDet_Release(detector);

    test_aggregation();
    test_mediadet();
    test_put_filter();
    test_samplegrabber();
    test_COM_sg_enumpins();

    ret = DeleteFileW(test_avi_filename);
    todo_wine ok(ret, "Failed to delete file, error %u.\n", GetLastError());
    ret = DeleteFileW(test_sound_avi_filename);
    todo_wine ok(ret, "Failed to delete file, error %u.\n", GetLastError());

    CoUninitialize();
}
