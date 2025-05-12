#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

static fz_context *global_ctx = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    global_ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
    if (!global_ctx)
        return 1;
    fz_register_document_handlers(global_ctx);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fz_context *ctx = global_ctx;
    fz_stream *stream;
    fz_document *doc;

    stream = NULL;
    doc = NULL;

    fz_var(stream);
    fz_var(doc);

    fz_try(ctx)
    {
        stream = fz_open_memory(ctx, data, size);
        doc = fz_open_document_with_stream(ctx, "pdf", stream);

        pdf_document *pdf_doc = pdf_specifics(ctx, doc);
        if (pdf_doc)
        {
            pdf_bake_document(ctx, pdf_doc, 1, 1);
        }
    }
    fz_always(ctx)
    {
        fz_drop_document(ctx, doc);
        fz_drop_stream(ctx, stream);
    }
    fz_catch(ctx)
    {
    }

    return 0;
}