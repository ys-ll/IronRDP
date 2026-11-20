use core::cell::RefCell;
use core::num::NonZeroU32;
#[cfg(target_arch = "wasm32")]
use std::rc::Rc;

#[cfg(target_arch = "wasm32")]
use anyhow::anyhow;
use ironrdp::pdu::geometry::InclusiveRectangle;
#[cfg(target_arch = "wasm32")]
use ironrdp::pdu::geometry::Rectangle as _;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{Clamped, JsCast as _};
#[cfg(target_arch = "wasm32")]
use web_sys::ImageData;
#[cfg(target_arch = "wasm32")]
use web_sys::{
    CanvasRenderingContext2d, HtmlCanvasElement, WebGl2RenderingContext, WebGlBuffer, WebGlProgram, WebGlShader,
    WebGlTexture,
};

/// Web render surface: blits each dirty region onto the canvas.
///
/// Prefers a WebGL2 path — the whole desktop lives in one GPU texture, each
/// dirty region is uploaded with a partial `texSubImage2D` and presented with
/// a single quad draw. Falls back to a Canvas2D `put_image_data` blit when
/// WebGL2 is unavailable. Both contexts are created opaque (`alpha: false`):
/// the framebuffer's alpha channel is not guaranteed (zero-init columns,
/// QOI-RGBA), but an opaque canvas never displays stored alpha, which keeps
/// the blit free of any per-pixel alpha fixups.
///
/// Drawing and presenting are separated: `draw` only uploads a region, and a
/// requestAnimationFrame loop presents the composed texture once per display
/// frame. Servers deliver scrolling updates as bursts of thin strips; without
/// the coalescing the client would paint each strip the moment it decodes,
/// which reads as visible stepped refresh.
pub(crate) struct Canvas {
    canvas: HtmlCanvasElement,
    renderer: Rc<RefCell<Renderer>>,
}

impl Canvas {
    pub(crate) fn new(render_canvas: HtmlCanvasElement, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<Self> {
        render_canvas.set_width(width.get());
        render_canvas.set_height(height.get());
        let renderer = match WebGl::new(&render_canvas, width, height) {
            Ok(webgl) => Renderer::WebGl2(webgl),
            Err(_) => Renderer::Canvas2d(Canvas2d::new(render_canvas.clone(), width, height)?),
        };
        let renderer = Rc::new(RefCell::new(renderer));

        #[cfg(target_arch = "wasm32")]
        spawn_present_loop(renderer.clone());

        Ok(Self {
            canvas: render_canvas,
            renderer,
        })
    }

    /// Resizes the backing store. Note: this also clears the canvas and resets
    /// context state; the cached renderer stays valid.
    pub(crate) fn resize(&mut self, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<()> {
        self.canvas.set_width(width.get());
        self.canvas.set_height(height.get());
        self.renderer.borrow_mut().resize(width, height)
    }

    pub(crate) fn draw(&self, buffer: &mut [u8], region: InclusiveRectangle) -> anyhow::Result<()> {
        self.renderer.borrow().draw(buffer, region)
    }
}

enum Renderer {
    WebGl2(WebGl),
    Canvas2d(Canvas2d),
}

impl Renderer {
    /// Uploads a region into the render target. Cheap by design: presentation
    /// happens on the rAF loop, not here.
    fn draw(&self, buffer: &mut [u8], region: InclusiveRectangle) -> anyhow::Result<()> {
        match self {
            Renderer::WebGl2(webgl) => webgl.upload(buffer, region),
            Renderer::Canvas2d(canvas2d) => canvas2d.draw(buffer, region),
        }
    }

    /// Composes and presents the current texture content.
    fn present(&self) {
        match self {
            Renderer::WebGl2(webgl) => webgl.present(),
            Renderer::Canvas2d(_) => {}
        }
    }

    fn resize(&mut self, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<()> {
        match self {
            Renderer::WebGl2(webgl) => webgl.resize(width, height),
            Renderer::Canvas2d(canvas2d) => Ok(canvas2d.resize(width, height)),
        }
    }
}

/// The full-desktop GPU texture plus the quad program that presents it.
struct WebGl {
    ctx: WebGl2RenderingContext,
    _program: WebGlProgram,
    _position_buffer: WebGlBuffer,
    _tex_coord_buffer: WebGlBuffer,
    texture: WebGlTexture,
}

impl WebGl {
    fn new(canvas: &HtmlCanvasElement, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<Self> {
        let options = js_sys::Object::new();
        for (name, value) in [
            ("alpha", false),
            ("antialias", false),
            ("depth", false),
            ("stencil", false),
            // The texture is the source of truth and every present redraws the
            // full quad; keeping the drawing buffer avoids black flashes for
            // composites that happen between two draws.
            ("preserveDrawingBuffer", true),
        ] {
            js_sys::Reflect::set(
                &options,
                &wasm_bindgen::JsValue::from_str(name),
                &wasm_bindgen::JsValue::from(value),
            )
            .map_err(|err| anyhow!("failed to build the webgl2 context options: {err:?}"))?;
        }

        let ctx = canvas
            .get_context_with_context_options("webgl2", &options)
            .map_err(|err| anyhow!("get_context(\"webgl2\") failed: {err:?}"))?
            .ok_or_else(|| anyhow!("canvas has no webgl2 context"))?
            .dyn_into::<WebGl2RenderingContext>()
            .map_err(|_| anyhow!("webgl2 context is not a WebGl2RenderingContext"))?;

        let program = link_program(&ctx)?;
        ctx.use_program(Some(&program));

        let position_buffer = ctx
            .create_buffer()
            .ok_or_else(|| anyhow!("failed to create the position buffer"))?;
        ctx.bind_buffer(WebGl2RenderingContext::ARRAY_BUFFER, Some(&position_buffer));
        let positions = js_sys::Float32Array::from(QUAD_POSITIONS.as_slice());
        ctx.buffer_data_with_array_buffer_view(
            WebGl2RenderingContext::ARRAY_BUFFER,
            &positions,
            WebGl2RenderingContext::STATIC_DRAW,
        );
        let position_location = ctx.get_attrib_location(&program, "a_position");
        if position_location == -1 {
            return Err(anyhow!("a_position attribute not found"));
        }
        ctx.vertex_attrib_pointer_with_i32(
            position_location as u32,
            2,
            WebGl2RenderingContext::FLOAT,
            false,
            0,
            0,
        );
        ctx.enable_vertex_attrib_array(position_location as u32);

        let tex_coord_buffer = ctx
            .create_buffer()
            .ok_or_else(|| anyhow!("failed to create the tex coord buffer"))?;
        ctx.bind_buffer(WebGl2RenderingContext::ARRAY_BUFFER, Some(&tex_coord_buffer));
        let tex_coords = js_sys::Float32Array::from(QUAD_TEX_COORDS.as_slice());
        ctx.buffer_data_with_array_buffer_view(
            WebGl2RenderingContext::ARRAY_BUFFER,
            &tex_coords,
            WebGl2RenderingContext::STATIC_DRAW,
        );
        let tex_coord_location = ctx.get_attrib_location(&program, "a_tex_coord");
        if tex_coord_location == -1 {
            return Err(anyhow!("a_tex_coord attribute not found"));
        }
        ctx.vertex_attrib_pointer_with_i32(
            tex_coord_location as u32,
            2,
            WebGl2RenderingContext::FLOAT,
            false,
            0,
            0,
        );
        ctx.enable_vertex_attrib_array(tex_coord_location as u32);

        let texture = ctx
            .create_texture()
            .ok_or_else(|| anyhow!("failed to create the desktop texture"))?;
        ctx.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&texture));
        ctx.tex_parameteri(
            WebGl2RenderingContext::TEXTURE_2D,
            WebGl2RenderingContext::TEXTURE_MIN_FILTER,
            WebGl2RenderingContext::NEAREST as i32,
        );
        ctx.tex_parameteri(
            WebGl2RenderingContext::TEXTURE_2D,
            WebGl2RenderingContext::TEXTURE_MAG_FILTER,
            WebGl2RenderingContext::NEAREST as i32,
        );
        ctx.tex_parameteri(
            WebGl2RenderingContext::TEXTURE_2D,
            WebGl2RenderingContext::TEXTURE_WRAP_S,
            WebGl2RenderingContext::CLAMP_TO_EDGE as i32,
        );
        ctx.tex_parameteri(
            WebGl2RenderingContext::TEXTURE_2D,
            WebGl2RenderingContext::TEXTURE_WRAP_T,
            WebGl2RenderingContext::CLAMP_TO_EDGE as i32,
        );

        ctx.viewport(0, 0, width.get() as i32, height.get() as i32);
        allocate_texture(&ctx, width.get(), height.get())?;

        Ok(Self {
            ctx,
            _program: program,
            _position_buffer: position_buffer,
            _tex_coord_buffer: tex_coord_buffer,
            texture,
        })
    }

    fn resize(&mut self, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<()> {
        self.ctx.viewport(0, 0, width.get() as i32, height.get() as i32);
        allocate_texture(&self.ctx, width.get(), height.get())
    }

    /// Uploads a region into the desktop texture. No presentation here.
    fn upload(&self, buffer: &mut [u8], region: InclusiveRectangle) -> anyhow::Result<()> {
        let ctx = &self.ctx;
        ctx.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&self.texture));
        // SAFETY: the view borrows the wasm linear memory for the duration of
        // the texSubImage2D call below; no wasm allocation can happen between
        // the two because the call is a single statement without allocation.
        let pixels = unsafe { js_sys::Uint8Array::view(buffer) };
        ctx.tex_sub_image_2d_with_i32_and_i32_and_u32_and_type_and_array_buffer_view_and_src_offset(
            WebGl2RenderingContext::TEXTURE_2D,
            0,
            region.left as i32,
            region.top as i32,
            region.width() as i32,
            region.height() as i32,
            WebGl2RenderingContext::RGBA,
            WebGl2RenderingContext::UNSIGNED_BYTE,
            &pixels,
            0,
        )
        .map_err(|err| anyhow!("texSubImage2D failed: {err:?}"))?;
        Ok(())
    }

    /// Presents the composed desktop texture with a single quad draw.
    fn present(&self) {
        self.ctx.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&self.texture));
        self.ctx.draw_arrays(WebGl2RenderingContext::TRIANGLE_STRIP, 0, 4);
    }
}

/// Uploads an empty texture of the given size (content arrives per region).
///
/// The PBO-offset overload would raise GL_INVALID_OPERATION without a bound
/// PIXEL_UNPACK_BUFFER, leaving the texture without a data store; the
/// no-source variant allocates the data store directly.
fn allocate_texture(ctx: &WebGl2RenderingContext, width: u32, height: u32) -> anyhow::Result<()> {
    ctx.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_u8_array(
        WebGl2RenderingContext::TEXTURE_2D,
        0,
        WebGl2RenderingContext::RGBA as i32,
        width as i32,
        height as i32,
        0,
        WebGl2RenderingContext::RGBA,
        WebGl2RenderingContext::UNSIGNED_BYTE,
        None,
    )
    .map_err(|err| anyhow!("texImage2D allocation failed: {err:?}"))
}

/// The fullscreen quad. Texture coordinates are V-flipped: GL texture row 0
/// holds the first row of the uploaded data, which is the top row of the
/// remote desktop.
const QUAD_POSITIONS: [f32; 8] = [-1.0, -1.0, 1.0, -1.0, -1.0, 1.0, 1.0, 1.0];
const QUAD_TEX_COORDS: [f32; 8] = [0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0];

const VERTEX_SHADER_SOURCE: &str = "#version 300 es
in vec2 a_position;
in vec2 a_tex_coord;
out vec2 v_tex_coord;
void main() {
    gl_Position = vec4(a_position, 0.0, 1.0);
    v_tex_coord = a_tex_coord;
}";

const FRAGMENT_SHADER_SOURCE: &str = "#version 300 es
precision mediump float;
in vec2 v_tex_coord;
uniform sampler2D u_texture;
out vec4 out_color;
void main() {
    out_color = texture(u_texture, v_tex_coord);
}";

fn link_program(ctx: &WebGl2RenderingContext) -> anyhow::Result<WebGlProgram> {
    let vertex_shader = compile_shader(ctx, WebGl2RenderingContext::VERTEX_SHADER, VERTEX_SHADER_SOURCE)?;
    let fragment_shader = compile_shader(ctx, WebGl2RenderingContext::FRAGMENT_SHADER, FRAGMENT_SHADER_SOURCE)?;

    let program = ctx
        .create_program()
        .ok_or_else(|| anyhow!("failed to create the WebGL program"))?;
    ctx.attach_shader(&program, &vertex_shader);
    ctx.attach_shader(&program, &fragment_shader);
    ctx.link_program(&program);
    ctx.delete_shader(Some(&vertex_shader));
    ctx.delete_shader(Some(&fragment_shader));

    if ctx
        .get_program_parameter(&program, WebGl2RenderingContext::LINK_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(program)
    } else {
        let message = ctx
            .get_program_info_log(&program)
            .unwrap_or_else(|| "unable to link the WebGL program".to_owned());
        Err(anyhow!("WebGL program link failed: {message}"))
    }
}

fn compile_shader(ctx: &WebGl2RenderingContext, shader_type: u32, source: &str) -> anyhow::Result<WebGlShader> {
    let shader = ctx
        .create_shader(shader_type)
        .ok_or_else(|| anyhow!("failed to create the WebGL shader"))?;
    ctx.shader_source(&shader, source);
    ctx.compile_shader(&shader);
    if ctx
        .get_shader_parameter(&shader, WebGl2RenderingContext::COMPILE_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(shader)
    } else {
        let message = ctx
            .get_shader_info_log(&shader)
            .unwrap_or_else(|| "unable to compile the WebGL shader".to_owned());
        ctx.delete_shader(Some(&shader));
        Err(anyhow!("WebGL shader compile failed: {message}"))
    }
}

/// The Canvas2D fallback, used when WebGL2 is unavailable.
struct Canvas2d {
    canvas: HtmlCanvasElement,
    ctx: CanvasRenderingContext2d,
}

impl Canvas2d {
    fn new(render_canvas: HtmlCanvasElement, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<Self> {
        render_canvas.set_width(width.get());
        render_canvas.set_height(height.get());
        let ctx = context_2d(&render_canvas)?;

        Ok(Self {
            canvas: render_canvas,
            ctx,
        })
    }

    fn resize(&mut self, width: NonZeroU32, height: NonZeroU32) {
        self.canvas.set_width(width.get());
        self.canvas.set_height(height.get());
    }

    /// Canvas2D has no separate present step: `put_image_data` paints
    /// immediately.
    fn draw(&self, buffer: &mut [u8], region: InclusiveRectangle) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let image = ImageData::new_with_u8_clamped_array_and_sh(
                Clamped(&*buffer),
                u32::from(region.width()),
                u32::from(region.height()),
            )
            .map_err(|err| anyhow!("ImageData::new failed: {err:?}"))?;
            self.ctx
                .put_image_data(&image, f64::from(region.left), f64::from(region.top))
                .map_err(|err| anyhow!("put_image_data failed: {err:?}"))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&self.ctx, buffer, region);
            unimplemented!("web canvas is only available on wasm32")
        }
    }
}

/// Acquires the opaque canvas 2D context (wasm only; panics on other targets).
fn context_2d(canvas: &HtmlCanvasElement) -> anyhow::Result<CanvasRenderingContext2d> {
    #[cfg(target_arch = "wasm32")]
    {
        let options = js_sys::Object::new();
        js_sys::Reflect::set(
            &options,
            &wasm_bindgen::JsValue::from_str("alpha"),
            &wasm_bindgen::JsValue::from(false),
        )
        .map_err(|err| anyhow!("failed to build the 2d context options: {err:?}"))?;

        canvas
            .get_context_with_context_options("2d", &options)
            .map_err(|err| anyhow!("get_context(\"2d\") failed: {err:?}"))?
            .ok_or_else(|| anyhow!("canvas has no 2d context"))?
            .dyn_into::<CanvasRenderingContext2d>()
            .map_err(|_| anyhow!("2d context is not a CanvasRenderingContext2d"))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = canvas;
        unimplemented!("web canvas is only available on wasm32")
    }
}

/// Spawns the requestAnimationFrame loop that presents the composed texture
/// once per display frame. The renderer is kept alive by the closure for the
/// lifetime of the page.
#[cfg(target_arch = "wasm32")]
fn spawn_present_loop(renderer: Rc<RefCell<Renderer>>) {
    use wasm_bindgen::prelude::Closure;

    let f: Rc<RefCell<Option<Closure<dyn FnMut()>>>> = Rc::new(RefCell::new(None));
    let g = f.clone();
    *g.borrow_mut() = Some(Closure::wrap(Box::new(move || {
        renderer.borrow().present();
        let window = web_sys::window().expect("no window");
        let scheduled = f.borrow();
        let next = scheduled.as_ref().unwrap().as_ref().unchecked_ref();
        window
            .request_animation_frame(next)
            .expect("failed to schedule the next present");
    })));

    let window = web_sys::window().expect("no window");
    window
        .request_animation_frame(g.borrow().as_ref().unwrap().as_ref().unchecked_ref())
        .expect("failed to schedule the present loop");
}
